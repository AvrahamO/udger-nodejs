// const main = './index.js';
const main = './index-alt.js';
const udgerParser = require(main)('udgerdb_v3.dat');

params = [{
  ua:'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
  ip:'66.249.64.73'
}, {
  ua:'Googlebot/2.1 (+http://www.google.com/bot.html)',
  ip:'192.168.0.1'
}]

runTest()

async function runTest() {

  console.log(main)
  for(let i = 0; i < 10; i++) {

    console.time(i)

    udgerParser.set(params[1]);
    let ret = udgerParser.parse({ json: true });
    console.timeEnd(i)
    // beautify json output with 4 spaces indent
    // console.log(JSON.stringify(ret, null, 4));
  }

}
