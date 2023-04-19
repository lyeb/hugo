// Copyright 2019 The Hugo Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pandoc converts content to HTML using Pandoc as an external helper.
package pandoc

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gohugoio/hugo/common/hexec"
	"github.com/gohugoio/hugo/htesting"
	"github.com/gohugoio/hugo/identity"
	"github.com/gohugoio/hugo/markup/internal"
	"github.com/gohugoio/hugo/markup/tableofcontents"

	"github.com/gohugoio/hugo/markup/converter"

	shellwords "github.com/mattn/go-shellwords"
)

// Provider is the package entry point.
var Provider converter.ProviderProvider = provider{}

type provider struct {
}

func (p provider) New(cfg converter.ProviderConfig) (converter.Provider, error) {
	return converter.NewProvider("pandoc", func(ctx converter.DocumentContext) (converter.Converter, error) {
		return &pandocConverter{
			ctx: ctx,
			cfg: cfg,
		}, nil
	}), nil
}

type pandocResult struct {
	converter.ResultRender
	toc *tableofcontents.Fragments
}

func (r pandocResult) TableOfContents() *tableofcontents.Fragments {
	return r.toc
}

type pandocConverter struct {
	ctx converter.DocumentContext
	cfg converter.ProviderConfig
}

func (c *pandocConverter) Convert(ctx converter.RenderContext) (converter.ResultRender, error) {
	b, err := c.getPandocContent(ctx.Src, c.ctx, "")
	if err != nil {
		return nil, err
	}
	if c.cfg.MarkupConfig.Pandoc.GenerateTOC {
		if pandocTocCmd == nil {
			return nil, fmt.Errorf("requested TOC generation but no PANDOC_TOC_CMD was given")
		}
		toc, err := c.extractToc(ctx.Src, c.ctx)
		if err != nil {
			return nil, err
		}
		return pandocResult{
			ResultRender: converter.Bytes(b),
			toc:          toc,
		}, nil
	}
	return converter.Bytes(b), nil
}

func (c *pandocConverter) ConvertFormat(ctx converter.RenderContext, format string) (converter.ResultRender, error) {
	b, err := c.getPandocContent(ctx.Src, c.ctx, format)
	if err != nil {
		return nil, err
	}
	return converter.Bytes(b), nil
}

func (c *pandocConverter) SupportsFormat(format string) bool {
	if !c.cfg.MarkupConfig.Pandoc.UseCustomOutputCommand {
		return false
	}
	if cmd, found := pandocFormatCmd(format); found {
		_, _, err := getPandocBinary(cmd)
		return err == nil
	}
	return false
}

func (c *pandocConverter) Supports(feature identity.Identity) bool {
	return false
}

// getPandocContent calls pandoc as an external helper to convert pandoc markdown to HTML.
func (c *pandocConverter) getPandocContent(src []byte, ctx converter.DocumentContext, format string) ([]byte, error) {
	logger := c.cfg.Logger
	var cmd string
	if c.cfg.MarkupConfig.Pandoc.UseCustomOutputCommand && format != "" {
		cmd, _ = pandocFormatCmd(format)
	} else {
		cmd = pandocCmd
	}
	bin, args, err := getPandocBinary(cmd)
	if err != nil {
		logger.Println("pandoc binary not found in $PATH: Please install.\n",
			"                 Leaving pandoc content unrendered.")
		return src, nil
	}
	return internal.ExternallyRenderContent(c.cfg, ctx, src, bin, args)
}

// extracts the table of contents with the custom command given by env var PANDOC_TOC_CMD
func (c *pandocConverter) extractToc(src []byte, ctx converter.DocumentContext) (*tableofcontents.Fragments, error) {
	bin, args, err := getPandocBinary(*pandocTocCmd)
	if err != nil {
		return nil, fmt.Errorf("pandoc binary for table of content generation not found")
	}
	res, err := internal.ExternallyRenderContent(c.cfg, ctx, src, bin, args)
	if err != nil {
		return nil, err
	}
	return c.parseToc(res)
}

type jsonHeader struct {
	ID    string
	Title string
	Level int
}

func (c *pandocConverter) parseToc(src []byte) (*tableofcontents.Fragments, error) {
	var (
		toc     tableofcontents.Builder
		headers []jsonHeader
	)

	err := json.Unmarshal(src, &headers)
	if err != nil {
		return nil, err
	}

	for row, header := range headers {
		toc.AddAt(&tableofcontents.Heading{
			Title: header.Title,
			ID:    header.ID,
		}, row, header.Level)
	}
	return toc.Build(), nil
}

var (
	pandocCmd = func() string {
		cmd, found := os.LookupEnv("PANDOC_CMD")
		if found {
			return cmd
		}
		return "pandoc --mathjax"
	}()
	pandocTocCmd = func() *string {
		cmd, found := os.LookupEnv("PANDOC_TOC_CMD")
		if found {
			return &cmd
		}
		return nil
	}()
)

func pandocFormatCmd(format string) (string, bool) {
	cmd, found := os.LookupEnv("PANDOC_CMD_FMT_" + strings.ToUpper(format))
	if found {
		return cmd, true
	}
	return pandocCmd, false
}

func getPandocBinary(cmd string) (string, []string, error) {
	var envs, args, err = shellwords.ParseWithEnvs(cmd)
	if err != nil {
		return "", nil, err
	}
	if len(envs) > 0 {
		return "", nil, fmt.Errorf("environment variables are not allowed in pandoc command")
	}
	if len(args) < 1 {
		return "", nil, fmt.Errorf("no pandoc executable provided")
	}
	if !hexec.InPath(args[0]) {
		return "", nil, fmt.Errorf("pandoc executable not in path")
	}
	return args[0], args[1:], nil
}

// Supports returns whether Pandoc is installed on this computer.
func Supports() bool {
	_, _, err := getPandocBinary(pandocCmd)
	var tocErr error = nil
	if pandocTocCmd != nil {
		_, _, tocErr = getPandocBinary(*pandocTocCmd)
	}
	hasBin := (err == nil) && (tocErr == nil)
	if htesting.SupportsAll() {
		if !hasBin {
			panic("pandoc binary not found")
		}
		return true
	}
	return hasBin
}
