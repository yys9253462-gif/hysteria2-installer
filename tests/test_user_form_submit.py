"""用户表单在页内提交（2026-11-12 修）。

旧实现：新建用户表单原生提交，删除表单确认后 form.submit()。重名、密码已被占用、
收回未完成、用户已不存在等错误时，浏览器跳到一张只有一行纯文本的错误页，填好的表单也没了。
按真实页面（表单的类名、action、字段都取自渲染出的 HTML）执行整份 portal.SCRIPT：
提交被拦下改走 fetch，失败就地提示并恢复按钮，成功（302）整页刷新回到用户列表。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

AFTER = r"""
async ctx => {
  const out = {};
  const fieldOf = (form, name) => form.fields.find(pair => pair[0] === name);
  const formFor = action => ctx.forms.find(f => (fieldOf(f, 'action') || [])[1] === action);
  const lastPost = () => ctx.requests.filter(r => r.method === 'POST').pop() || null;
  const submit = async form => {
    let prevented = false;
    for (const fn of form.listeners.submit || []) fn({preventDefault() { prevented = true; }});
    await ctx.tick();
    return prevented;
  };

  const create = formFor('create');
  fieldOf(create, 'user_id')[1] = 'buyer01';
  ctx.setRespond(() => new Response('用户 buyer01 已存在', {status: 409}));
  out.conflict = {prevented: await submit(create), post: lastPost(), alerts: ctx.alerts.splice(0),
                  reloads: ctx.reloads(), disabled: create.btn.disabled};
  ctx.setRespond(() => Promise.reject(new TypeError('Failed to fetch')));
  out.network = {prevented: await submit(create), alerts: ctx.alerts.splice(0), reloads: ctx.reloads(),
                 disabled: create.btn.disabled};
  ctx.setRespond(() => ({type: 'opaqueredirect', ok: false, status: 0, text: async () => ''}));
  out.created = {prevented: await submit(create), reloads: ctx.reloads(), hash: ctx.location.hash,
                 alerts: ctx.alerts.splice(0)};

  const del = formFor('delete');
  ctx.setRespond(() => new Response('User not found', {status: 404}));
  const prevented = await submit(del);
  ctx.els['confirm-btn-ok'].click();
  await ctx.tick();
  out.deleted = {prevented, post: lastPost(), alerts: ctx.alerts.splice(0), native: ctx.nativeSubmits.slice()};
  return out;
}
"""


@unittest.skipUnless(NODE, 'requires node')
class UserFormSubmitTests(unittest.TestCase):
    def test_user_forms_submit_in_page_and_report_failures_in_place(self):
        model = page_model(users={'buyer02': {'password': 'pw-test-only-02', 'status': 'active',
                                              'expires_at': 4102444800, 'created_at': 1}})
        report = run_portal_page(model, '#users', after=AFTER)
        self.assertEqual(report['errors'], [])
        after = report['after']

        conflict = after['conflict']
        self.assertTrue(conflict['prevented'], 'the create form still submits natively')
        self.assertIn('action=create', conflict['post']['body'])
        self.assertIn('user_id=buyer01', conflict['post']['body'])
        self.assertEqual(conflict['alerts'], ['用户 buyer01 已存在'])
        self.assertEqual(conflict['reloads'], 0)
        self.assertFalse(conflict['disabled'], 'the submit button stays disabled after a failure')

        self.assertEqual(after['network']['alerts'], ['请求异常: Failed to fetch'])
        self.assertEqual(after['network']['reloads'], 0)
        self.assertFalse(after['network']['disabled'])

        self.assertEqual(after['created']['reloads'], 1)
        self.assertEqual(after['created']['hash'], '#users')
        self.assertEqual(after['created']['alerts'], [])

        deleted = after['deleted']
        self.assertTrue(deleted['prevented'])
        self.assertEqual(deleted['native'], [], 'the delete form still submits natively after confirming')
        self.assertIn('action=delete', deleted['post']['body'])
        self.assertIn('user_id=buyer02', deleted['post']['body'])
        self.assertEqual(deleted['alerts'], ['User not found'])


if __name__ == '__main__':
    unittest.main()
