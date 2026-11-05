import { Pipe, PipeTransform } from '@angular/core';
import { Marked } from 'marked';

function escapeText(text: string): string {
  return text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

const markdown = new Marked({
  gfm: true,
  breaks: true,
  renderer: {
    html({ text }) { return escapeText(text); },
    image({ text }) { return escapeText(text); },
    link({ tokens }) { return this.parser.parseInline(tokens); }
  }
});

@Pipe({ name: 'assistantMarkdown', standalone: true })
export class AssistantMarkdownPipe implements PipeTransform {
  transform(text: string): string {
    return markdown.parse(text, { async: false });
  }
}
