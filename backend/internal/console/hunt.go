package console

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type HuntNode struct {
	Op, Field, Value string
	Children         []*HuntNode
}
type huntToken struct{ kind, value string }
type huntParser struct {
	tokens           []huntToken
	at, nodes, depth int
}

var huntNumbers = map[string]bool{}
var huntSubstrings = map[string]bool{}
var huntCI = map[string]bool{}

func init() {
	for _, field := range schema.HuntNumeric {
		huntNumbers[field] = true
	}
	for _, field := range schema.HuntSubstring {
		huntSubstrings[field] = true
	}
	for _, field := range schema.HuntCI {
		huntCI[field] = true
	}
}
func lexHunt(input string) ([]huntToken, error) {
	if len(input) > 8192 || strings.TrimSpace(input) == "" {
		return nil, errors.New("搜索条件为空或过长")
	}
	r := []rune(input)
	out := []huntToken{}
	for i := 0; i < len(r); {
		if unicode.IsSpace(r[i]) {
			i++
			continue
		}
		if r[i] < 32 {
			return nil, errors.New("搜索条件含控制字符")
		}
		c := r[i]
		if strings.ContainsRune(":()[]{}", c) {
			out = append(out, huntToken{string(c), string(c)})
			i++
			continue
		}
		if c == '<' || c == '>' {
			op := string(c)
			i++
			if i < len(r) && r[i] == '=' {
				op += "="
				i++
			}
			out = append(out, huntToken{"compare", op})
			continue
		}
		if c == '"' {
			i++
			var b strings.Builder
			closed := false
			for i < len(r) {
				c = r[i]
				i++
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' {
					if i >= len(r) {
						return nil, errors.New("搜索值末尾缺少转义字符")
					}
					c = r[i]
					i++
				}
				if c == '*' || c == '?' || c == '[' {
					b.WriteByte('\\')
				}
				b.WriteRune(c)
			}
			if !closed || b.Len() == 0 {
				return nil, errors.New("引号未闭合或搜索值为空")
			}
			out = append(out, huntToken{"value", b.String()})
			continue
		}
		var b strings.Builder
		for i < len(r) && !unicode.IsSpace(r[i]) && !strings.ContainsRune(":()[]{}<>", r[i]) {
			c = r[i]
			i++
			if c == '\\' {
				if i >= len(r) {
					return nil, errors.New("搜索值末尾缺少转义字符")
				}
				c = r[i]
				i++
				if strings.ContainsRune("*?[", c) {
					b.WriteByte('\\')
				}
			}
			b.WriteRune(c)
		}
		if b.Len() == 0 {
			return nil, errors.New("无效搜索值")
		}
		value := b.String()
		kind := "value"
		if value == "AND" || value == "OR" || value == "NOT" || value == "TO" {
			kind = value
		} else if strings.EqualFold(value, "and") || strings.EqualFold(value, "or") || strings.EqualFold(value, "not") {
			return nil, errors.New("布尔连接词必须大写：AND / OR / NOT")
		}
		if strings.ContainsAny(value, "~^") || value == "&&" || value == "||" || value == "!" {
			return nil, errors.New("不支持此搜索运算符")
		}
		out = append(out, huntToken{kind, value})
	}
	if len(out) > 2048 {
		return nil, errors.New("搜索条件过于复杂")
	}
	out = append(out, huntToken{"end", ""})
	return out, nil
}
func ParseHunt(input string) (*HuntNode, error) {
	tokens, err := lexHunt(input)
	if err != nil {
		return nil, err
	}
	p := huntParser{tokens: tokens}
	n, err := p.expression("", false)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != "end" {
		return nil, errors.New("Lucene 搜索语法无效")
	}
	return n, nil
}
func (p *huntParser) peek() huntToken { return p.tokens[p.at] }
func (p *huntParser) take() huntToken { v := p.peek(); p.at++; return v }
func (p *huntParser) node(n *HuntNode) (*HuntNode, error) {
	p.nodes++
	if p.nodes > 1024 {
		return nil, errors.New("搜索条件过于复杂")
	}
	return n, nil
}
func (p *huntParser) expression(field string, orMode bool) (*HuntNode, error) {
	left, err := p.andExpression(field)
	if err != nil {
		return nil, err
	}
	children := []*HuntNode{left}
	for p.peek().kind == "OR" {
		p.take()
		right, err := p.andExpression(field)
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return p.node(&HuntNode{Op: "or", Children: children})
}
func (p *huntParser) andExpression(field string) (*HuntNode, error) {
	left, err := p.atom(field)
	if err != nil {
		return nil, err
	}
	children := []*HuntNode{left}
	for {
		kind := p.peek().kind
		if kind == "end" || kind == ")" || kind == "OR" {
			break
		}
		if kind == "AND" {
			p.take()
		}
		right, err := p.atom(field)
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 1 {
		return left, nil
	}
	return p.node(&HuntNode{Op: "and", Children: children})
}
func (p *huntParser) atom(field string) (*HuntNode, error) {
	t := p.take()
	if t.kind == "NOT" {
		n, err := p.atom(field)
		if err != nil {
			return nil, err
		}
		return p.node(&HuntNode{Op: "not", Children: []*HuntNode{n}})
	}
	if t.kind == "(" {
		p.depth++
		if p.depth > 20 {
			return nil, errors.New("搜索条件嵌套过深")
		}
		n, err := p.expression(field, false)
		if err != nil {
			return nil, err
		}
		if p.take().kind != ")" {
			return nil, errors.New("搜索分组未闭合")
		}
		p.depth--
		return n, nil
	}
	if t.kind == "value" && p.peek().kind == ":" {
		if field != "" {
			return nil, errors.New("字段分组内不能再指定其他字段")
		}
		p.take()
		name, ok := schema.HuntFields[strings.ToLower(t.value)]
		if !ok {
			return nil, errors.New("未知字段：" + t.value)
		}
		return p.atom(name)
	}
	if t.kind == "compare" {
		if !huntNumbers[field] {
			return nil, errors.New("该字段不支持数值比较")
		}
		value := p.take()
		if value.kind != "value" {
			return nil, errors.New("比较条件缺少数值")
		}
		if _, err := parseNumber(value.value); err != nil {
			return nil, err
		}
		return p.node(&HuntNode{Op: "cmp", Field: field, Value: t.value + value.value})
	}
	if t.kind == "[" || t.kind == "{" {
		if !huntNumbers[field] {
			return nil, errors.New("范围条件需要数值字段")
		}
		lo, to, hi, end := p.take(), p.take(), p.take(), p.take()
		if lo.kind != "value" || hi.kind != "value" || to.kind != "TO" || (end.kind != "]" && end.kind != "}") {
			return nil, errors.New("无效范围条件")
		}
		parts := []*HuntNode{}
		if lo.value != "*" {
			if _, err := parseNumber(lo.value); err != nil {
				return nil, err
			}
			op := ">"
			if t.kind == "[" {
				op = ">="
			}
			parts = append(parts, &HuntNode{Op: "cmp", Field: field, Value: op + lo.value})
		}
		if hi.value != "*" {
			if _, err := parseNumber(hi.value); err != nil {
				return nil, err
			}
			op := "<"
			if end.kind == "]" {
				op = "<="
			}
			parts = append(parts, &HuntNode{Op: "cmp", Field: field, Value: op + hi.value})
		}
		if len(parts) == 0 {
			return p.node(&HuntNode{Op: "cmp", Field: field, Value: "*"})
		}
		if len(parts) == 1 {
			return p.node(parts[0])
		}
		return p.node(&HuntNode{Op: "and", Children: parts})
	}
	if t.kind != "value" {
		return nil, errors.New("搜索条件缺少值")
	}
	if huntNumbers[field] && t.value != "*" {
		if _, err := parseNumber(t.value); err != nil {
			return nil, err
		}
	}
	op := "cmp"
	if field == "" {
		op = "bare"
	}
	return p.node(&HuntNode{Op: op, Field: field, Value: t.value})
}

var numberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

func parseNumber(value string) (any, error) {
	if !numberPattern.MatchString(value) {
		return nil, errors.New("数值字段需要有限数值")
	}
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		return n, nil
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil, errors.New("数值超出范围")
	}
	if strings.ContainsAny(value, ".eE") {
		return n, nil
	}
	return nil, errors.New("整数超出范围")
}
func glob(pattern, value string) bool {
	var b strings.Builder
	b.WriteString("(?s)^")
	r := []rune(pattern)
	for i := 0; i < len(r); i++ {
		switch r[i] {
		case '\\':
			if i+1 < len(r) {
				i++
				b.WriteString(regexp.QuoteMeta(string(r[i])))
			} else {
				b.WriteString(`\\`)
			}
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '[':
			j := i + 1
			for j < len(r) && r[j] != ']' {
				j++
			}
			if j < len(r) {
				content := string(r[i+1 : j])
				if strings.HasPrefix(content, "!") {
					content = "^" + content[1:]
				}
				b.WriteByte('[')
				b.WriteString(content)
				b.WriteByte(']')
				i = j
			} else {
				b.WriteString(`\[`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(r[i])))
		}
	}
	b.WriteByte('$')
	expression, err := regexp.Compile(b.String())
	return err == nil && expression.MatchString(value)
}

func compileHunt(node *HuntNode, icase bool) (string, []any, error) {
	if node == nil {
		return "TRUE", nil, nil
	}
	switch node.Op {
	case "and", "or":
		parts := []string{}
		args := []any{}
		for _, child := range node.Children {
			part, values, err := compileHunt(child, icase)
			if err != nil {
				return "", nil, err
			}
			parts = append(parts, "("+part+")")
			args = append(args, values...)
		}
		return strings.Join(parts, " "+strings.ToUpper(node.Op)+" "), args, nil
	case "not":
		part, args, err := compileHunt(node.Children[0], icase)
		return "NOT COALESCE((" + part + "),FALSE)", args, err
	case "bare":
		column := "COALESCE(CASE WHEN type='flow' THEN flow_summary(app,proto,state,reason,sig) ELSE sig END,'')||' '||COALESCE(src,'')||' '||COALESCE(dst,'')||' '||COALESCE(app,'')||' '||COALESCE(reason,'')||' '||COALESCE(cat,'')||' '||COALESCE(proto,'')||' '||COALESCE(type,'')"
		value := node.Value
		if icase {
			column = "hunt_fold(" + column + ")"
			value = strings.ToLower(value)
		}
		if strings.ContainsAny(value, "*?") {
			return "hunt_glob(" + column + ",?)", []any{"*" + value + "*"}, nil
		}
		return "INSTR(" + column + ",?)>0", []any{value}, nil
	case "cmp":
		field, value := node.Field, node.Value
		if strings.HasPrefix(field, "mitre_") {
			return "hunt_metadata(raw,?,?,?)", []any{field, value, icase}, nil
		}
		column := ""
		for _, pair := range schema.Columns {
			if pair[1] != nil && *pair[1] == field {
				column = *pair[0]
				break
			}
		}
		for key, val := range map[string]string{"dns": "dnsname", "file": "fname", "size": "fsize", "ts": "(ts/1000.0)", "sig_id": "sid", "tuple_hash": "tuple_hash(src,sport,dst,dport,proto)"} {
			if key == field {
				column = val
			}
		}
		if field == "level" {
			column = "CASE WHEN sev=1 THEN 'high' WHEN sev=2 THEN 'medium' WHEN sev>=3 THEN 'low' WHEN sid>0 AND type IN ('alert','drop') THEN 'unknown' ELSE '' END"
			value = strings.ToLower(strings.TrimSpace(value))
			if alias, ok := schema.HuntLevelAliases[value]; ok {
				value = alias
			}
		}
		if field == "tuple_hash" {
			column = "CASE WHEN COALESCE(community,'')!='' OR COALESCE(flow_id,0)>0 THEN NULL ELSE tuple_hash(src,sport,dst,dport,proto) END"
			value = strings.ToLower(value)
		}
		if field == "httpver" {
			column = "CASE WHEN type='quic' THEN '' WHEN COALESCE(httpver,'')='' AND (type='http2' OR (type='http' AND app='http2')) THEN 'HTTP/2' ELSE httpver END"
		}
		if field == "sig" {
			column = "CASE WHEN type='flow' THEN flow_summary(app,proto,state,reason,sig) ELSE sig END"
		}
		if column == "" {
			return "", nil, errors.New("搜索字段没有有效投影")
		}
		if value == "*" {
			if huntNumbers[field] {
				return column + " IS NOT NULL", nil, nil
			}
			return "COALESCE(" + column + ",'')!=''", nil, nil
		}
		if huntNumbers[field] {
			op := "="
			for _, prefix := range []string{">=", "<=", ">", "<"} {
				if strings.HasPrefix(value, prefix) {
					op = prefix
					value = strings.TrimPrefix(value, prefix)
					break
				}
			}
			n, err := parseNumber(value)
			return column + op + "?", []any{n}, err
		}
		if (field == "src" || field == "dst") && strings.Contains(value, "/") {
			return "hunt_network(" + column + ",?)", []any{value}, nil
		}
		if (icase && field != "community") || huntCI[field] {
			column = "hunt_fold(" + column + ")"
			value = strings.ToLower(value)
		}
		if strings.ContainsAny(value, "*?[") {
			if huntSubstrings[field] {
				if !strings.HasPrefix(value, "*") {
					value = "*" + value
				}
				if !strings.HasSuffix(value, "*") {
					value += "*"
				}
			}
			return "hunt_glob(COALESCE(" + column + ",''),?)", []any{value}, nil
		}
		if huntSubstrings[field] {
			return "INSTR(COALESCE(" + column + ",''),?)>0", []any{value}, nil
		}
		return "COALESCE(" + column + ",'')=?", []any{value}, nil
	}
	return "", nil, errors.New("无效搜索节点")
}
