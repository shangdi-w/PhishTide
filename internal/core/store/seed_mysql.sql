-- 钓鱼演练平台 · 内置模板 seed（MySQL）
-- 用法：mysql -uroot -p phishsim < internal/store/seed_mysql.sql
-- 幂等：INSERT IGNORE 按固定 id 写入，重复执行不重复。

INSERT IGNORE INTO email_templates (id, name, subject, html, text) VALUES
(1, '密码过期提醒', '【重要】您的邮箱密码即将过期，请立即处理',
'<!doctype html><html><body style="font-family:system-ui,sans-serif;color:#1f2933">
<p>{{.FirstName}} {{.LastName}}，您好：</p>
<p>您的企业邮箱账户 <strong>{{.Email}}</strong> 的登录密码将于今日到期。为避免影响正常办公，请在 24 小时内登录并更新密码。</p>
<p><a href="{{.TrackingURL}}" style="color:#2563eb">点此更新密码</a></p>
<p>如未及时更新，您的邮箱将被暂停使用。</p>
<p style="color:#6b7280;font-size:12px">此邮件由系统自动发送，请勿直接回复。<br>{{.FromName}}</p>
<img src="{{.TrackingPixel}}" width="1" height="1" style="display:none">
</body></html>',
'{{.FirstName}} {{.LastName}}，您好：

您的企业邮箱账户 {{.Email}} 的登录密码将于今日到期。为避免影响正常办公，请在 24 小时内登录并更新密码。

请点击以下链接完成密码更新：
{{.TrackingURL}}

如未及时更新，您的邮箱将被暂停使用。

此邮件由系统自动发送，请勿直接回复。

{{.FromName}}'),

(2, '工资条调整通知', '关于本月工资条调整的确认通知',
'<!doctype html><html><body style="font-family:system-ui,sans-serif;color:#1f2933">
<p>{{.FirstName}} {{.LastName}}（{{.Position}}），您好：</p>
<p>您本月的工资条信息已更新，请登录内部系统核对确认。</p>
<p><a href="{{.TrackingURL}}" style="color:#2563eb">查看工资条</a></p>
<p>请于本周内完成确认，逾期将影响本月薪资发放。</p>
<p style="color:#6b7280;font-size:12px">{{.FromName}}</p>
<img src="{{.TrackingPixel}}" width="1" height="1" style="display:none">
</body></html>',
'{{.FirstName}} {{.LastName}}（{{.Position}}），您好：

您本月的工资条信息已更新，请登录内部系统核对确认。

查看地址：{{.TrackingURL}}

请于本周内完成确认，逾期将影响本月薪资发放。

{{.FromName}}'),

(3, '办公系统账号验证', '请完成企业办公系统账号安全验证',
'<!doctype html><html><body style="font-family:system-ui,sans-serif;color:#1f2933">
<p>{{.FirstName}}，您好：</p>
<p>为配合公司信息安全管理要求，所有员工需完成一次账号安全验证。请点击以下链接并登录您的企业账号：</p>
<p><a href="{{.TrackingURL}}" style="color:#2563eb">立即验证</a></p>
<p>验证完成后账号方可正常使用。感谢配合。</p>
<p style="color:#6b7280;font-size:12px">{{.FromName}}</p>
<img src="{{.TrackingPixel}}" width="1" height="1" style="display:none">
</body></html>',
'{{.FirstName}}，您好：

为配合公司信息安全管理要求，所有员工需完成一次账号安全验证。请点击以下链接并登录您的企业账号：

{{.TrackingURL}}

验证完成后账号方可正常使用。感谢配合。

{{.FromName}}');

INSERT IGNORE INTO landing_pages (id, name, kind, source_url, body, content_type, capture_credentials, capture_passwords, redirect_url) VALUES
(1, '统一身份认证登录', 'template', '',
'<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>统一身份认证</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px;width:380px;max-width:92vw}
h1{font-size:20px;margin:0 0 4px;color:#1f2933}p.sub{font-size:13px;color:#6b7280;margin:0 0 24px}
label{display:block;font-size:13px;color:#374151;margin-bottom:6px}
input{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;margin-bottom:18px}
button{width:100%;padding:11px;background:#2563eb;color:#fff;border:0;border-radius:8px;font-size:15px;cursor:pointer}
button:hover{background:#1d4ed8}.foot{font-size:12px;color:#9ca3af;text-align:center;margin-top:20px}
</style></head><body>
<form class="card" method="post" action="__SUBMIT_URL__">
<h1>统一身份认证</h1>
<p class="sub">请使用企业账号登录</p>
<label>用户名 / 邮箱</label>
<input name="username" type="text" autocomplete="username" placeholder="name@company.com" required>
<label>密码</label>
<input name="password" type="password" autocomplete="current-password" placeholder="••••••••" required>
<button type="submit">登 录</button>
<div class="foot">© 内部系统 · 请勿与他人共享账号</div>
</form>
</body></html>',
'text/html; charset=utf-8', 1, 1, ''),

(2, '企业邮箱登录', 'template', '',
'<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>企业邮箱</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",system-ui,sans-serif;background:#eaf1fb;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#fff;border-radius:4px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:360px;max-width:92vw;padding:32px 28px}
.logo{font-size:22px;color:#0078d4;margin:0 0 20px;font-weight:600}
label{display:block;font-size:13px;color:#444;margin:0 0 5px}
input{width:100%;padding:9px 10px;border:1px solid #a0a0a0;font-size:14px;margin-bottom:16px}
input:focus{outline:none;border-color:#0078d4}
button{width:100%;padding:10px;background:#0078d4;color:#fff;border:0;font-size:15px;cursor:pointer}
button:hover{background:#106ebe}
.keep{font-size:13px;color:#333;margin:14px 0}.hint{font-size:12px;color:#666}
</style></head><body>
<form class="box" method="post" action="__SUBMIT_URL__">
<div class="logo">企业邮箱</div>
<label>邮箱地址</label>
<input name="email" type="text" autocomplete="username" placeholder="name@company.com" required>
<label>密码</label>
<input name="password" type="password" autocomplete="current-password" required>
<button type="submit">登录</button>
<label class="keep"><input type="checkbox" name="keep" value="1" checked> 保持登录状态</label>
<div class="hint">无法访问？联系 IT 支持。</div>
</form>
</body></html>',
'text/html; charset=utf-8', 1, 1, ''),

(3, '两步登录（账号→密码）', 'template', '',
'<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>账号登录</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#f5f7fa;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.08);padding:36px;width:400px;max-width:92vw}
h1{font-size:20px;margin:0 0 20px;color:#1f2933}
label{display:block;font-size:13px;color:#374151;margin-bottom:6px}
input{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;margin-bottom:16px}
button{width:100%;padding:11px;background:#2563eb;color:#fff;border:0;border-radius:8px;font-size:15px;cursor:pointer}
.err{color:#dc2626;font-size:13px;margin-bottom:12px;display:none}
.step{display:none}.step.active{display:block}
</style></head><body>
<form class="card" method="post" action="__SUBMIT_URL__" onsubmit="return check()">
<h1>账号登录</h1>
<div id="s1" class="step active">
  <label>邮箱地址</label>
  <input name="email" id="em" type="text" autocomplete="username" placeholder="name@company.com">
  <button type="button" onclick="next()">下一步</button>
</div>
<div id="s2" class="step">
  <label>密码</label>
  <input name="password" id="pw" type="password" autocomplete="current-password" placeholder="请输入密码">
  <div id="err" class="err">密码不能为空，请重新输入</div>
  <button type="submit">登录</button>
</div>
</form>
<script>
function next(){var e=document.getElementById("em").value.trim();if(!e){alert("请输入邮箱地址");return;}document.getElementById("s1").classList.remove("active");document.getElementById("s2").classList.add("active");document.getElementById("pw").focus();}
function check(){if(!document.getElementById("pw").value){document.getElementById("err").style.display="block";document.getElementById("pw").value="";document.getElementById("pw").focus();return false;}return true;}
</script>
</body></html>',
'text/html; charset=utf-8', 1, 1, '');
