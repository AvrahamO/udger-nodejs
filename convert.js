const fs = require('fs');
const path = require('path');

if(!process.argv[2]) {
  console.log(
    'Usage: node ' + path.basename(process.argv[1])+ ' <path/to/udgerdb_v3.dat>' +
    '\n' +
    'A new file `udgerdb_v3.json` will be created in current directory'
  );
  process.exit(1)
}

const inFile = path.resolve(process.argv[2]);
const output = {};

const Database = require('better-sqlite3');
const db = new Database(inFile, { fileMustExist: true });

// Import tables
const tables_list = db.prepare('SELECT name FROM sqlite_master where type = ?');
for (let table of tables_list.iterate('table')) {
  const stmt = db.prepare(`SELECT * FROM ${table.name}`);
  output[table.name] = {
    columns: stmt.columns().reduce(prepareColumns, {}),
    data: stmt.raw().all()
  };
}

// Sort sequence tables
const sequenceTables = [
  'udger_client_regex',
  'udger_os_regex',
  'udger_deviceclass_regex',
  'udger_devicename_regex',
  'udger_ip_class'
];
for (let table of sequenceTables) {
  let { columns, data } = output[table];
  data.sort((a,b) => {
    return a[columns.sequence] - b[columns.sequence];
  })
}

// Sort ip list ascending
var ipCol = output.udger_ip_list.columns.ip;
output.udger_ip_list.data.sort((a,b) => {
  return a[ipCol].localeCompare(b[ipCol]);
})

// Replace foreign id with foreign index
const relationships = [
  ['udger_crawler_list', 'class_id', 'udger_crawler_class'],
  ['udger_client_regex', 'client_id', 'udger_client_list'],
  ['udger_client_list', 'class_id', 'udger_client_class'],
  ['udger_os_regex', 'os_id', 'udger_os_list'],
  ['udger_client_os_relation', 'os_id', 'udger_os_list'],
  ['udger_deviceclass_regex', 'deviceclass_id', 'udger_deviceclass_list'],
  ['udger_client_class', 'deviceclass_id', 'udger_deviceclass_list'],
  ['udger_devicename_list', 'brand_id', 'udger_devicename_brand'],
  ['udger_ip_list', 'class_id', 'udger_ip_class'],
  ['udger_ip_list', 'crawler_id', 'udger_crawler_list'],
  ['udger_datacenter_range', 'datacenter_id', 'udger_datacenter_list'],
  ['udger_datacenter_range6', 'datacenter_id', 'udger_datacenter_list'],
];
for(let [leftTable, foreignColumn, rightTable] of relationships) {
  let { columns, data } = output[leftTable];
  let rightIndexes = mapIndexesByID(rightTable);
  foreignColumn = columns[foreignColumn];
  data.forEach(row => {
    row[foreignColumn] = rightIndexes[row[foreignColumn]];
  })
}

fs.writeFileSync(`${path.parse(inFile).name}.json`, JSON.stringify(output));


// Convert columns array to object { col: index }
function prepareColumns(acc, column, index) {
  acc[column.name] = index;
  return acc;
}

// Return object with { id: index }
function mapIndexesByID(table) {
  let { columns, data } = output[table];
  return data.reduce((acc, v, i) => {
    let id = v[columns.id];
    acc[id] = i;
    return acc;
  }, {})
}
