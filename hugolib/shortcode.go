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

package hugolib

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gohugoio/hugo/helpers"

	"errors"

	"github.com/gohugoio/hugo/common/herrors"

	"github.com/gohugoio/hugo/parser/pageparser"
	"github.com/gohugoio/hugo/resources/page"

	"github.com/gohugoio/hugo/common/maps"
	"github.com/gohugoio/hugo/common/text"
	"github.com/gohugoio/hugo/common/urls"
	"github.com/gohugoio/hugo/output"

	bp "github.com/gohugoio/hugo/bufferpool"
	"github.com/gohugoio/hugo/tpl"
)

var (
	_ urls.RefLinker  = (*ShortcodeWithPage)(nil)
	_ pageWrapper     = (*ShortcodeWithPage)(nil)
	_ text.Positioner = (*ShortcodeWithPage)(nil)
)

// ShortcodeWithPage is the "." context in a shortcode template.
type ShortcodeWithPage struct {
	Params        any
	Inner         template.HTML
	Page          page.Page
	Parent        *ShortcodeWithPage
	Name          string
	IsNamedParams bool

	// Zero-based ordinal in relation to its parent. If the parent is the page itself,
	// this ordinal will represent the position of this shortcode in the page content.
	Ordinal int

	// Indentation before the opening shortcode in the source.
	indentation string

	innerDeindentInit sync.Once
	innerDeindent     template.HTML

	// pos is the position in bytes in the source file. Used for error logging.
	posInit   sync.Once
	posOffset int
	pos       text.Position

	scratch *maps.Scratch
}

// InnerDeindent returns the (potentially de-indented) inner content of the shortcode.
func (scp *ShortcodeWithPage) InnerDeindent() template.HTML {
	if scp.indentation == "" {
		return scp.Inner
	}
	scp.innerDeindentInit.Do(func() {
		b := bp.GetBuffer()
		text.VisitLinesAfter(string(scp.Inner), func(s string) {
			if strings.HasPrefix(s, scp.indentation) {
				b.WriteString(strings.TrimPrefix(s, scp.indentation))
			} else {
				b.WriteString(s)
			}
		})
		scp.innerDeindent = template.HTML(b.String())
		bp.PutBuffer(b)
	})

	return scp.innerDeindent
}

// Position returns this shortcode's detailed position. Note that this information
// may be expensive to calculate, so only use this in error situations.
func (scp *ShortcodeWithPage) Position() text.Position {
	scp.posInit.Do(func() {
		if p, ok := mustUnwrapPage(scp.Page).(pageContext); ok {
			scp.pos = p.posOffset(scp.posOffset)
		}
	})
	return scp.pos
}

// Site returns information about the current site.
func (scp *ShortcodeWithPage) Site() page.Site {
	return scp.Page.Site()
}

// Ref is a shortcut to the Ref method on Page. It passes itself as a context
// to get better error messages.
func (scp *ShortcodeWithPage) Ref(args map[string]any) (string, error) {
	return scp.Page.RefFrom(args, scp)
}

// RelRef is a shortcut to the RelRef method on Page. It passes itself as a context
// to get better error messages.
func (scp *ShortcodeWithPage) RelRef(args map[string]any) (string, error) {
	return scp.Page.RelRefFrom(args, scp)
}

// Scratch returns a scratch-pad scoped for this shortcode. This can be used
// as a temporary storage for variables, counters etc.
func (scp *ShortcodeWithPage) Scratch() *maps.Scratch {
	if scp.scratch == nil {
		scp.scratch = maps.NewScratch()
	}
	return scp.scratch
}

// Get is a convenience method to look up shortcode parameters by its key.
func (scp *ShortcodeWithPage) Get(key any) any {
	if scp.Params == nil {
		return nil
	}
	if reflect.ValueOf(scp.Params).Len() == 0 {
		return nil
	}

	var x reflect.Value

	switch key.(type) {
	case int64, int32, int16, int8, int:
		if reflect.TypeOf(scp.Params).Kind() == reflect.Map {
			// We treat this as a non error, so people can do similar to
			// {{ $myParam := .Get "myParam" | default .Get 0 }}
			// Without having to do additional checks.
			return nil
		} else if reflect.TypeOf(scp.Params).Kind() == reflect.Slice {
			idx := int(reflect.ValueOf(key).Int())
			ln := reflect.ValueOf(scp.Params).Len()
			if idx > ln-1 {
				return ""
			}
			x = reflect.ValueOf(scp.Params).Index(idx)
		}
	case string:
		if reflect.TypeOf(scp.Params).Kind() == reflect.Map {
			x = reflect.ValueOf(scp.Params).MapIndex(reflect.ValueOf(key))
			if !x.IsValid() {
				return ""
			}
		} else if reflect.TypeOf(scp.Params).Kind() == reflect.Slice {
			// We treat this as a non error, so people can do similar to
			// {{ $myParam := .Get "myParam" | default .Get 0 }}
			// Without having to do additional checks.
			return nil
		}
	}

	return x.Interface()
}

func (scp *ShortcodeWithPage) page() page.Page {
	return scp.Page
}

func createShortcodePlaceholder(id string, ordinal int) string {
	return `<hugo-shrtcdplchld id="` + id + `" ordinal="` + strconv.Itoa(ordinal) + `"></hugo-shrtcdplchld>`
}

type shortcode struct {
	name      string
	isInline  bool  // inline shortcode. Any inner will be a Go template.
	isClosing bool  // whether a closing tag was provided
	inner     []any // string or nested shortcode
	params    any   // map or array
	ordinal   int
	err       error

	indentation string // indentation from source.

	info   tpl.Info       // One of the output formats (arbitrary)
	templs []tpl.Template // All output formats

	// If set, the rendered shortcode is sent as part of the surrounding content
	// to Goldmark and similar.
	// Before Hug0 0.55 we didn't send any shortcode output to the markup
	// renderer, and this flag told Hugo to process the {{ .Inner }} content
	// separately.
	// The old behaviour can be had by starting your shortcode template with:
	//    {{ $_hugo_config := `{ "version": 1 }`}}
	doMarkup bool

	// the placeholder in the source when passed to Goldmark etc.
	// This also identifies the rendered shortcode.
	placeholder string

	pos    int // the position in bytes in the source file
	length int // the length in bytes in the source file
}

func (s shortcode) insertPlaceholder() bool {
	return !s.doMarkup || s.configVersion() == 1
}

func (s shortcode) needsInner() bool {
	return s.info != nil && s.info.ParseInfo().IsInner
}

func (s shortcode) configVersion() int {
	if s.info == nil {
		// Not set for inline shortcodes.
		return 2
	}

	return s.info.ParseInfo().Config.Version
}

func (s shortcode) innerString() string {
	var sb strings.Builder

	for _, inner := range s.inner {
		sb.WriteString(inner.(string))
	}

	return sb.String()
}

func (sc shortcode) String() string {
	// for testing (mostly), so any change here will break tests!
	var params any
	switch v := sc.params.(type) {
	case map[string]any:
		// sort the keys so test assertions won't fail
		var keys []string
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		tmp := make(map[string]any)

		for _, k := range keys {
			tmp[k] = v[k]
		}
		params = tmp

	default:
		// use it as is
		params = sc.params
	}

	return fmt.Sprintf("%s(%q, %t){%s}", sc.name, params, sc.doMarkup, sc.inner)
}

type shortcodeHandler struct {
	p *pageState

	s *Site

	// Ordered list of shortcodes for a page.
	shortcodes []*shortcode

	// All the shortcode names in this set.
	nameSet   map[string]bool
	nameSetMu sync.RWMutex

	// Configuration
	enableInlineShortcodes bool
}

func newShortcodeHandler(p *pageState, s *Site) *shortcodeHandler {
	sh := &shortcodeHandler{
		p:                      p,
		s:                      s,
		enableInlineShortcodes: s.ExecHelper.Sec().EnableInlineShortcodes,
		shortcodes:             make([]*shortcode, 0, 4),
		nameSet:                make(map[string]bool),
	}

	return sh
}

const (
	innerNewlineRegexp = "\n"
	innerCleanupRegexp = `\A<p>(.*)</p>\n\z`
	innerCleanupExpand = "$1"
)

func prepareShortcode(
	ctx context.Context,
	level int,
	s *Site,
	tplVariants tpl.TemplateVariants,
	sc *shortcode,
	parent *ShortcodeWithPage,
	p *pageState) (shortcodeRenderer, error) {

	toParseErr := func(err error) error {
		return p.parseError(fmt.Errorf("failed to render shortcode %q: %w", sc.name, err), p.source.parsed.Input(), sc.pos)
	}

	// Allow the caller to delay the rendering of the shortcode if needed.
	var fn shortcodeRenderFunc = func(ctx context.Context) ([]byte, bool, error) {
		r, err := doRenderShortcode(ctx, level, s, tplVariants, sc, parent, p)
		if err != nil {
			return nil, false, toParseErr(err)
		}
		b, hasVariants, err := r.renderShortcode(ctx)
		if err != nil {
			return nil, false, toParseErr(err)
		}
		return b, hasVariants, nil
	}

	return fn, nil

}

func doRenderShortcode(
	ctx context.Context,
	level int,
	s *Site,
	tplVariants tpl.TemplateVariants,
	sc *shortcode,
	parent *ShortcodeWithPage,
	p *pageState) (shortcodeRenderer, error) {
	var tmpl tpl.Template

	// Tracks whether this shortcode or any of its children has template variations
	// in other languages or output formats. We are currently only interested in
	// the output formats, so we may get some false positives -- we
	// should improve on that.
	var hasVariants bool

	if sc.isInline {
		if !p.s.ExecHelper.Sec().EnableInlineShortcodes {
			return zeroShortcode, nil
		}
		templName := path.Join("_inline_shortcode", p.File().Path(), sc.name)
		if sc.isClosing {
			templStr := sc.innerString()

			var err error
			tmpl, err = s.TextTmpl().Parse(templName, templStr)
			if err != nil {
				fe := herrors.NewFileErrorFromName(err, p.File().Filename())
				pos := fe.Position()
				pos.LineNumber += p.posOffset(sc.pos).LineNumber
				fe = fe.UpdatePosition(pos)
				return zeroShortcode, p.wrapError(fe)
			}

		} else {
			// Re-use of shortcode defined earlier in the same page.
			var found bool
			tmpl, found = s.TextTmpl().Lookup(templName)
			if !found {
				return zeroShortcode, fmt.Errorf("no earlier definition of shortcode %q found", sc.name)
			}
		}
	} else {
		var found, more bool
		tmpl, found, more = s.Tmpl().LookupVariant(sc.name, tplVariants)
		if !found {
			s.Log.Errorf("Unable to locate template for shortcode %q in page %q", sc.name, p.File().Path())
			return zeroShortcode, nil
		}
		hasVariants = hasVariants || more
	}

	data := &ShortcodeWithPage{Ordinal: sc.ordinal, posOffset: sc.pos, indentation: sc.indentation, Params: sc.params, Page: newPageForShortcode(p), Parent: parent, Name: sc.name}
	if sc.params != nil {
		data.IsNamedParams = reflect.TypeOf(sc.params).Kind() == reflect.Map
	}

	if len(sc.inner) > 0 {
		var inner string
		for _, innerData := range sc.inner {
			switch innerData := innerData.(type) {
			case string:
				inner += innerData
			case *shortcode:
				s, err := prepareShortcode(ctx, level+1, s, tplVariants, innerData, data, p)
				if err != nil {
					return zeroShortcode, err
				}
				ss, more, err := s.renderShortcodeString(ctx)
				hasVariants = hasVariants || more
				if err != nil {
					return zeroShortcode, err
				}
				inner += ss
			default:
				s.Log.Errorf("Illegal state on shortcode rendering of %q in page %q. Illegal type in inner data: %s ",
					sc.name, p.File().Path(), reflect.TypeOf(innerData))
				return zeroShortcode, nil
			}
		}

		// Pre Hugo 0.55 this was the behaviour even for the outer-most
		// shortcode.
		if sc.doMarkup && (level > 0 || sc.configVersion() == 1) {
			var err error
			b, err := p.pageOutput.contentRenderer.ParseAndRenderContent(ctx, []byte(inner), false)
			if err != nil {
				return zeroShortcode, err
			}

			newInner := b.Bytes()

			// If the type is “” (unknown) or “markdown”, we assume the markdown
			// generation has been performed. Given the input: `a line`, markdown
			// specifies the HTML `<p>a line</p>\n`. When dealing with documents as a
			// whole, this is OK. When dealing with an `{{ .Inner }}` block in Hugo,
			// this is not so good. This code does two things:
			//
			// 1.  Check to see if inner has a newline in it. If so, the Inner data is
			//     unchanged.
			// 2   If inner does not have a newline, strip the wrapping <p> block and
			//     the newline.
			switch p.m.markup {
			case "", "markdown":
				if match, _ := regexp.MatchString(innerNewlineRegexp, inner); !match {
					cleaner, err := regexp.Compile(innerCleanupRegexp)

					if err == nil {
						newInner = cleaner.ReplaceAll(newInner, []byte(innerCleanupExpand))
					}
				}
			}

			// TODO(bep) we may have plain text inner templates.
			data.Inner = template.HTML(newInner)
		} else {
			data.Inner = template.HTML(inner)
		}

	}

	result, err := renderShortcodeWithPage(ctx, s.Tmpl(), tmpl, data)

	if err != nil && sc.isInline {
		fe := herrors.NewFileErrorFromName(err, p.File().Filename())
		pos := fe.Position()
		pos.LineNumber += p.posOffset(sc.pos).LineNumber
		fe = fe.UpdatePosition(pos)
		return zeroShortcode, fe
	}

	if len(sc.inner) == 0 && len(sc.indentation) > 0 {
		b := bp.GetBuffer()
		i := 0
		text.VisitLinesAfter(result, func(line string) {
			// The first line is correctly indented.
			if i > 0 {
				b.WriteString(sc.indentation)
			}
			i++
			b.WriteString(line)
		})

		result = b.String()
		bp.PutBuffer(b)
	}

	return prerenderedShortcode{s: result, hasVariants: hasVariants}, err
}

func (s *shortcodeHandler) hasShortcodes() bool {
	return s != nil && len(s.shortcodes) > 0
}

func (s *shortcodeHandler) addName(name string) {
	s.nameSetMu.Lock()
	defer s.nameSetMu.Unlock()
	s.nameSet[name] = true
}

func (s *shortcodeHandler) transferNames(in *shortcodeHandler) {
	s.nameSetMu.Lock()
	defer s.nameSetMu.Unlock()
	for k := range in.nameSet {
		s.nameSet[k] = true
	}

}

func (s *shortcodeHandler) hasName(name string) bool {
	s.nameSetMu.RLock()
	defer s.nameSetMu.RUnlock()
	_, ok := s.nameSet[name]
	return ok
}

func (s *shortcodeHandler) prepareShortcodesForPage(ctx context.Context, p *pageState, f output.Format) (map[string]shortcodeRenderer, error) {
	rendered := make(map[string]shortcodeRenderer)

	tplVariants := tpl.TemplateVariants{
		Language:     p.Language().Lang,
		OutputFormat: f,
	}

	for _, v := range s.shortcodes {
		s, err := prepareShortcode(ctx, 0, s.s, tplVariants, v, nil, p)
		if err != nil {
			return nil, err
		}
		rendered[v.placeholder] = s

	}

	return rendered, nil
}

func (s *shortcodeHandler) parseError(err error, input []byte, pos int) error {
	if s.p != nil {
		return s.p.parseError(err, input, pos)
	}
	return err
}

var shortcodeAttributeRegex = regexp.MustCompile(`^(id|p-(\d{1,6})|n-(\S+))$`)

func createCustomShortcode(attributes map[string]string, content string, pos int, length int) (*shortcode, error) {
	posParams := map[int]string{}
	nmdParams := map[string]string{}
	idFound := false
	id := ""
	for key, val := range attributes {
		match := shortcodeAttributeRegex.FindStringSubmatch(key)
		if match == nil {
			return nil, fmt.Errorf("custom shortcode has unexpected attribute format")
		}
		switch match[1][0] {
		case 'i':
			// shortcode id
			idFound = true
			id = val

		case 'p':
			// positional parameter
			p, _ := strconv.Atoi(match[2]) // is always convertible due to regexp check
			_, found := posParams[p]
			if found {
				return nil, fmt.Errorf("ambiguous positional parameter")
			}
			posParams[p] = val

		case 'n':
			// named parameter
			_, found := nmdParams[match[3]]
			if found {
				return nil, fmt.Errorf("ambiguous named parameter")
			}
			nmdParams[match[3]] = val
		}
	}
	if !idFound {
		return nil, fmt.Errorf("attribute id missing in custom shortcode")
	}
	params := any(nil)
	if len(posParams) == 0 {
		if len(nmdParams) != 0 {
			m := map[string]any{}
			for key, val := range nmdParams {
				m[key] = pageparser.StandaloneValTyped(val)
			}
			params = m
		}
	} else {
		if len(nmdParams) != 0 {
			return nil, fmt.Errorf("mixed positional and named parameters")
		} else {
			a := []any{}
			for i := 0; i < len(posParams); i++ {
				val, found := posParams[i]
				if !found {
					return nil, fmt.Errorf("positional parameters not in order (starting from zero)")
				}
				a = append(a, pageparser.StandaloneValTyped(val))
			}
			params = a
		}
	}

	sc := &shortcode{name: id, params: params, inner: []any{content}, pos: pos, length: length, isInline: false, doMarkup: false, indentation: "", ordinal: -1}

	return sc, nil
}

// pageTokens state:
// - before: positioned just before the shortcode start
// - after: shortcode(s) consumed (plural when they are nested)
func (s *shortcodeHandler) extractShortcode(ordinal, level int, source []byte, pt *pageparser.Iterator) (*shortcode, error) {
	if s == nil {
		panic("handler nil")
	}
	sc := &shortcode{ordinal: ordinal}

	// Back up one to identify any indentation.
	if pt.Pos() > 0 {
		pt.Backup()
		item := pt.Next()
		if item.IsIndentation() {
			sc.indentation = item.ValStr(source)
		}
	}

	cnt := 0
	nestedOrdinal := 0
	nextLevel := level + 1
	closed := false
	const errorPrefix = "failed to extract shortcode"

Loop:
	for {
		currItem := pt.Next()
		switch {
		case currItem.IsLeftShortcodeDelim():
			next := pt.Peek()
			if next.IsRightShortcodeDelim() {
				// no name: {{< >}} or {{% %}}
				return sc, errors.New("shortcode has no name")
			}
			if next.IsShortcodeClose() {
				continue
			}

			if cnt > 0 {
				// nested shortcode; append it to inner content
				pt.Backup()
				nested, err := s.extractShortcode(nestedOrdinal, nextLevel, source, pt)
				nestedOrdinal++
				if nested != nil && nested.name != "" {
					s.addName(nested.name)
				}

				if err == nil {
					sc.inner = append(sc.inner, nested)
				} else {
					return sc, err
				}

			} else {
				sc.doMarkup = currItem.IsShortcodeMarkupDelimiter()
			}

			cnt++

		case currItem.IsRightShortcodeDelim():
			// we trust the template on this:
			// if there's no inner, we're done
			if !sc.isInline {
				if !sc.info.ParseInfo().IsInner {
					return sc, nil
				}
			}

		case currItem.IsShortcodeClose():
			closed = true
			next := pt.Peek()
			if !sc.isInline {
				if !sc.needsInner() {
					if next.IsError() {
						// return that error, more specific
						continue
					}
					return nil, fmt.Errorf("%s: shortcode %q does not evaluate .Inner or .InnerDeindent, yet a closing tag was provided", errorPrefix, next.ValStr(source))
				}
			}
			if next.IsRightShortcodeDelim() {
				// self-closing
				pt.Consume(1)
			} else {
				sc.isClosing = true
				pt.Consume(2)
			}

			return sc, nil
		case currItem.IsText():
			sc.inner = append(sc.inner, currItem.ValStr(source))
		case currItem.Type == pageparser.TypeEmoji:
			// TODO(bep) avoid the duplication of these "text cases", to prevent
			// more of #6504 in the future.
			val := currItem.ValStr(source)
			if emoji := helpers.Emoji(val); emoji != nil {
				sc.inner = append(sc.inner, string(emoji))
			} else {
				sc.inner = append(sc.inner, val)
			}
		case currItem.IsShortcodeName():

			sc.name = currItem.ValStr(source)

			// Used to check if the template expects inner content.
			templs := s.s.Tmpl().LookupVariants(sc.name)
			if templs == nil {
				return nil, fmt.Errorf("%s: template for shortcode %q not found", errorPrefix, sc.name)
			}

			sc.info = templs[0].(tpl.Info)
			sc.templs = templs
		case currItem.IsInlineShortcodeName():
			sc.name = currItem.ValStr(source)
			sc.isInline = true
		case currItem.IsShortcodeParam():
			if !pt.IsValueNext() {
				continue
			} else if pt.Peek().IsShortcodeParamVal() {
				// named params
				if sc.params == nil {
					params := make(map[string]any)
					params[currItem.ValStr(source)] = pt.Next().ValTyped(source)
					sc.params = params
				} else {
					if params, ok := sc.params.(map[string]any); ok {
						params[currItem.ValStr(source)] = pt.Next().ValTyped(source)
					} else {
						return sc, fmt.Errorf("%s: invalid state: invalid param type %T for shortcode %q, expected a map", errorPrefix, params, sc.name)
					}
				}
			} else {
				// positional params
				if sc.params == nil {
					var params []any
					params = append(params, currItem.ValTyped(source))
					sc.params = params
				} else {
					if params, ok := sc.params.([]any); ok {
						params = append(params, currItem.ValTyped(source))
						sc.params = params
					} else {
						return sc, fmt.Errorf("%s: invalid state: invalid param type %T for shortcode %q, expected a slice", errorPrefix, params, sc.name)
					}
				}
			}
		case currItem.IsDone():
			if !currItem.IsError() {
				if !closed && sc.needsInner() {
					return sc, fmt.Errorf("%s: shortcode %q must be closed or self-closed", errorPrefix, sc.name)
				}
			}
			// handled by caller
			pt.Backup()
			break Loop

		}
	}
	return sc, nil
}

type shortcodeSpan struct {
	isCustom   bool
	attributes map[string]string
	content    []any
	start      int
	end        int
}

func (s *shortcodeSpan) getPlaceholder() string {
	if s.isCustom {
		return ""
	}
	id, found1 := s.attributes["id"]
	ordStr, found2 := s.attributes["ordinal"]
	if !found1 || !found2 {
		return ""
	}
	ord, err := strconv.Atoi(ordStr)
	if err != nil {
		return ""
	}
	return createShortcodePlaceholder(id, ord)
}

var interruptRegex = regexp.MustCompile(`<(/?hugo-shrtcdplchld|p>\s*(</?hugo-shrtcdplchld))`)
var elementStartRegex = regexp.MustCompile(`^<hugo-shrtcdplchld(-custom)?([^>]*)>(\s*</p>)?`)
var parEndRegex = regexp.MustCompile(`^\s*</p>`)
var htmlAttrRegex = regexp.MustCompile(`([^\s=]+)="([^"]*)"`)

func parseShortcodeSpans(
	source []byte,
	offset int,
) (int, []any, bool, error) {
	content := []any{}
	start := offset
	for {
		tmp := shortcodeSpan{attributes: map[string]string{}}

		match := interruptRegex.FindSubmatchIndex(source[start:])
		if match == nil {
			// no more shortcodes in source
			content = append(content, string(source[start:]))
			return len(source), content, false, nil
		}

		inPar := false
		elementStart := start + match[0]
		switch source[start+match[2]] {
		case 'p':
			// paragraph before shortcode
			inPar = true
			elementStart = start + match[4]
			if source[elementStart+1] == '/' {
				// closing tag inside paragraph => return early with info
				content = append(content, string(source[start:start+match[0]]))
				return elementStart, content, true, nil
			}

		case '/':
			// closing tag => return early
			content = append(content, string(source[start:elementStart]))
			return elementStart, content, false, nil
		}

		elementMatch := elementStartRegex.FindSubmatch(source[elementStart:])
		if elementMatch == nil {
			return -1, nil, false, fmt.Errorf("missing `>` in start-tag of hugo-shrtcdplchld element")
		}

		if elementMatch[3] != nil {
			// paragraph end directly after shortcode start
			inPar = false
		}

		attrsMatch := htmlAttrRegex.FindAllSubmatch(elementMatch[2], -1)
		if attrsMatch == nil {
			// no attributes in shortcode
			attrsMatch = [][][]byte{}
		}

		for _, attr := range attrsMatch {
			tmp.attributes[string(attr[1])] = string(attr[2])
		}

		tmp.start = start + match[0]
		tmp.isCustom = (elementMatch[1] != nil)

		// recursively parse content
		end, innerContent, parStartBefore, err := parseShortcodeSpans(source, elementStart+len(elementMatch[0]))
		if err != nil {
			return -1, nil, false, err
		}
		if parStartBefore && inPar {
			return -1, nil, false, fmt.Errorf("found unexpected paragraph start-tag in front of a closing hugo-shrtcdplchld element")
		}

		endTag := "</hugo-shrtcdplchld>"
		if tmp.isCustom {
			endTag = "</hugo-shrtcdplchld-custom>"
		}
		if !bytes.HasPrefix(source[end:], []byte(endTag)) {
			return -1, nil, false, fmt.Errorf("no matching end-tag for hugo-shrtcdplchld element found")
		}
		end += len(endTag)

		if inPar || parStartBefore {
			// maybe read ending paragraph element
			parMatch := parEndRegex.FindIndex(source[end:])
			if parMatch != nil {
				end += parMatch[1]
			} else if inPar {
				// do not substitute paragraph because shortcode is not alone
				tmp.start = elementStart
			} else {
				return -1, nil, false, fmt.Errorf("expected paragraph end after closing hugo-shrtcdplchld element")
			}
		}

		tmp.content = innerContent
		tmp.end = end

		content = append(content, string(source[start:tmp.start]), tmp)

		start = end
	}
}

// Replace prefixed shortcode tokens with the real content.
// Note: This function will rewrite the input slice.
func expandShortcodeTokens(
	ctx context.Context,
	source []byte,
	tokenHandler func(ctx context.Context, token string) ([]byte, error),
	customTokenHandler func(ctx context.Context, attributes map[string]string, content string, pos int, length int) ([]byte, error),
) ([]byte, error) {
	end, content, _, err := parseShortcodeSpans(source, 0)
	if err != nil {
		return nil, err
	}
	if end != len(source) {
		return nil, fmt.Errorf("unexpected hugo-shrtcdplchld end-tag")
	}

	offset := 0
	for _, span := range content {
		span, isSpan := span.(shortcodeSpan)
		if isSpan {
			offset, source, _, err = expandShortcode(span, offset, ctx, source, tokenHandler, customTokenHandler)
			if err != nil {
				return nil, err
			}
		}
	}
	return source, nil
}

func expandShortcode(
	span shortcodeSpan,
	offset int,
	ctx context.Context,
	source []byte,
	tokenHandler func(ctx context.Context, token string) ([]byte, error),
	customTokenHandler func(ctx context.Context, attributes map[string]string, content string, pos int, length int) ([]byte, error),
) (int, []byte, []byte, error) {
	l := len(source)
	newOffset := offset

	newVal, err := []byte(nil), error(nil)
	if span.isCustom {
		childContent := []byte{}
		for _, t := range span.content {
			switch t := t.(type) {
			case string:
				childContent = append(childContent, t...)

			case shortcodeSpan:
				// recursively expand child
				var expanded []byte
				newOffset, source, expanded, err = expandShortcode(t, newOffset, ctx, source, tokenHandler, customTokenHandler)
				if err != nil {
					return -1, nil, nil, err
				}
				childContent = append(childContent, expanded...)

			default:
				// this should never happen
				return -1, nil, nil, fmt.Errorf("unknown child type in content of custom shortcode")
			}
		}
		newVal, err = customTokenHandler(ctx, span.attributes, string(childContent), span.start+offset, span.end+newOffset)
	} else {
		newVal, err = tokenHandler(ctx, span.getPlaceholder())
	}
	if err != nil {
		return -1, nil, nil, err
	}
	pre := source[:span.start+offset]
	post := source[span.end+newOffset:]
	source = append(pre, append(newVal, post...)...)

	return offset + len(source) - l, source, newVal, nil
}

func renderShortcodeWithPage(ctx context.Context, h tpl.TemplateHandler, tmpl tpl.Template, data *ShortcodeWithPage) (string, error) {
	buffer := bp.GetBuffer()
	defer bp.PutBuffer(buffer)

	err := h.ExecuteWithContext(ctx, tmpl, buffer, data)
	if err != nil {
		return "", fmt.Errorf("failed to process shortcode: %w", err)
	}
	return buffer.String(), nil
}
