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
	"os"
	"strings"

	"github.com/gohugoio/hugo/common/hexec"
	"github.com/gohugoio/hugo/htesting"
	"github.com/gohugoio/hugo/identity"
	"github.com/gohugoio/hugo/markup/internal"

	"github.com/gohugoio/hugo/markup/converter"
)

// Provider is the package entry point.
var Provider converter.ProviderProvider = provider{}

// pandoc default binary name
const pandocBinary = "pandoc"

// pandoc default arguments
var pandocArgs = []string{"--mathjax"}

type provider struct {
}

func (p provider) New(cfg converter.ProviderConfig) ([]converter.Provider, error) {
	res := make([]converter.Provider, 0, 1+len(cfg.MarkupConfig.Pandoc.CustomMarkupFormats))
	res = append(res,
		converter.NewProvider("pandoc", []string{"pdc"}, func(ctx converter.DocumentContext) (converter.Converter, error) {
			return &pandocConverter{
				ctx:  ctx,
				cfg:  cfg,
				cmd:  pandocBinary,
				args: pandocArgs,
			}, nil
		}))
	for _, fmt := range cfg.MarkupConfig.Pandoc.CustomMarkupFormats {
		env := "PANDOC_FMT_" + strings.ToUpper(fmt)
		cmd := os.Getenv(env)
		if cmd == "" {
			cfg.Logger.Printf("environment variable %s not set. Ignoring custom pandoc format %s.\n", env, fmt)
		} else {
			res = append(res,
				converter.NewProvider(fmt, []string{}, func(ctx converter.DocumentContext) (converter.Converter, error) {
					return &pandocConverter{
						ctx:  ctx,
						cfg:  cfg,
						cmd:  cmd,
						args: []string{},
					}, nil
				}))
		}
	}
	return res, nil
}

type pandocConverter struct {
	ctx  converter.DocumentContext
	cfg  converter.ProviderConfig
	cmd  string
	args []string
}

func (c *pandocConverter) Convert(ctx converter.RenderContext) (converter.ResultRender, error) {
	b, err := c.getPandocContent(ctx.Src, c.ctx)
	if err != nil {
		return nil, err
	}
	return converter.Bytes(b), nil
}

func (c *pandocConverter) Supports(feature identity.Identity) bool {
	return false
}

// getPandocContent calls pandoc as an external helper to convert pandoc markdown to HTML.
func (c *pandocConverter) getPandocContent(src []byte, ctx converter.DocumentContext) ([]byte, error) {
	logger := c.cfg.Logger
	if !hexec.InPath(c.cmd) {
		logger.Printf("pandoc binary %s not found in $PATH: Please install the missing files.\n"+
			"                 Leaving pandoc content unrendered.\n", c.cmd)
		return src, nil
	}
	return internal.ExternallyRenderContent(c.cfg, ctx, src, c.cmd, c.args)
}

func getPandocBinaryName() string {
	if hexec.InPath(pandocBinary) {
		return pandocBinary
	}
	return ""
}

// Supports returns whether Pandoc is installed on this computer.
func Supports() bool {
	hasBin := getPandocBinaryName() != ""
	if htesting.SupportsAll() {
		if !hasBin {
			panic("pandoc not installed")
		}
		return true
	}
	return hasBin
}
