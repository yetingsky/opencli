/**
 * 集思录个人 Timeline 适配器
 * 需要登录状态，访问 /home/mine/#all 页面
 */
import { cli, Strategy } from "../../registry.js";
import type { IPage } from "../../types.js";

cli({
  site: "jisilu",
  name: "timeline",
  description: "集思录个人时间线 (需登录)",
  domain: "www.jisilu.cn",
  strategy: Strategy.COOKIE,
  browser: true,

  args: [{ name: "limit", type: "int", default: 20, help: "返回条目数量" }],

  columns: ["id", "type", "title", "author", "content", "url"],

  func: async (page: IPage, kwargs) => {
    const limit = kwargs.limit || 20;

    await page.goto("https://www.jisilu.cn/home/mine/#all");
    await page.wait(3);

    const data = await page.evaluate(`
      (function() {
        var results = [];
        var items = document.querySelectorAll('.aw-item');

        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          var linkEl = item.querySelector('a[href*="/question/"]');
          var titleEl = item.querySelector('h4 a, .title a');
          var authorEl = item.querySelector('.aw-user-name');
          var contentEl = item.querySelector('.markitup-box, .aw-question-content, .content');

          if (linkEl || titleEl) {
            var url = (linkEl && linkEl.href) || (titleEl && titleEl.href) || '';
            var idMatch = url.match(/question\\/(\\d+)/);
            var title = (titleEl && titleEl.textContent.trim()) || (linkEl && linkEl.textContent.trim()) || '';
            var content = '';
            if (contentEl) {
              content = contentEl.textContent.trim();
            }

            var type = 'post';
            if (item.querySelector('.aw-answer-list') || item.textContent.indexOf('回复了') > -1) {
              type = 'reply';
            }

            results.push({
              id: idMatch ? idMatch[1] : '',
              type: type,
              title: title.substring(0, 100),
              author: (authorEl && authorEl.textContent.trim()) || '',
              content: content.substring(0, 200),
              url: url
            });
          }
        }

        return results;
      })()
    `);

    return (data || []).slice(0, limit);
  },
});
