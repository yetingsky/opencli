/**
 * 集思录帖子详情适配器
 * 获取帖子正文和评论
 */
import { cli, Strategy } from "../../registry.js";
import type { IPage } from "../../types.js";

cli({
  site: "jisilu",
  name: "question",
  description: "集思录帖子详情 (正文+评论)",
  domain: "www.jisilu.cn",
  strategy: Strategy.PUBLIC,
  browser: true,

  args: [
    { name: "id", type: "str", required: true, help: "帖子ID或URL" },
    { name: "limit", type: "int", default: 50, help: "评论数量限制" },
  ],

  columns: ["type", "author", "content", "time", "likes"],

  func: async (page: IPage, kwargs) => {
    let questionId = kwargs.id;
    const idMatch = kwargs.id.match(/question\/(\d+)/);
    if (idMatch) questionId = idMatch[1];

    const url = `https://www.jisilu.cn/question/${questionId}`;
    await page.goto(url);
    await page.wait(2);

    const data = await page.evaluate(`
      (function() {
        var results = [];
        var title = document.querySelector('h1');
        var titleText = title ? title.textContent.trim() : '';
        var postContent = document.querySelector('.aw-question-detail-txt');
        var postText = postContent ? postContent.textContent.trim() : '';
        var postTimeEl = document.querySelector('.aw-question-detail-meta');
        var postTimeText = postTimeEl ? postTimeEl.textContent : '';
        var postTimeMatch = postTimeText.match(/发表时间\\s*(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2})/);
        var postTime = postTimeMatch ? postTimeMatch[1] : '';

        results.push({
          type: 'post',
          author: '',
          content: postText.substring(0, 500),
          time: postTime,
          likes: 0
        });

        var answers = document.querySelectorAll('.aw-item[id^="answer_list_"]');
        var limit = ${kwargs.limit};

        for (var i = 0; i < answers.length && i < limit; i++) {
          var answer = answers[i];
          var authorEl = answer.querySelector('.aw-user-name');
          var contentEl = answer.querySelector('.markitup-box');
          var timeEl = answer.querySelector('.aw-dynamic-topic-meta span');

          if (authorEl && contentEl) {
            var author = authorEl.textContent.trim();
            var content = contentEl.textContent.trim().substring(0, 300);
            var timeText = timeEl ? timeEl.textContent : '';
            var timeMatch = timeText.match(/(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2})/);
            var time = timeMatch ? timeMatch[1] : '';

            results.push({
              type: 'reply',
              author: author,
              content: content,
              time: time,
              likes: 0
            });
          }
        }

        return results;
      })()
    `);

    return data;
  },
});
