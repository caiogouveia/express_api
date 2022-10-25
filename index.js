const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port  = 3000;

app.set('view engine', 'ejs');

app.get("/", (req, res) => {
  res.render('home.ejs');
});

app.listen(port, () => {
  console.log('Server started.');
  }
)
