const fs = require('fs');
const Database = require('better-sqlite3');

const file = 'test/db/udgerdb_v3_test.dat';
// const file = 'udgerdb_v3.dat';
const db = new Database(file, { fileMustExist: true });

const tables_list = db.prepare('SELECT name FROM sqlite_master where type = ?');


for (let table of tables_list.iterate('table')) {
  exportTable(table.name);
}

function exportTable(table) {
  const stmt = db.prepare(`SELECT * FROM ${table}`);
  var output = {
    headers: stmt.columns().map(c => c.name),
    data: stmt.raw().all()
  };  
  fs.writeFileSync(`out/${table}.json`, JSON.stringify(output))
}  
