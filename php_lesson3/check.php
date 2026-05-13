<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>確認ページ</title>
</head>
<body>
  <h1>入力内容の確認</h1>

<?php
  $nickname = $_POST['nickname'];
  $email    = $_POST['email'];
  $goiken   = $_POST['goiken'];

  if ($nickname == '') {
    print 'ニックネームが入力されていません<br>';
  } else {
    print 'ようこそ ' . $nickname . ' 様<br>';
  }

  if ($email == '') {
    print 'メールアドレスが入力されていません<br>';
  } else {
    print $email . '<br>';
  }

  if ($goiken == '') {
    print 'ごいけんが入力されていません<br>';
  } else {
    print $goiken . '<br>';
  }
?>

  <br>
  <button onclick="history.back()">前のページにもどる</button>
</body>
</html>
