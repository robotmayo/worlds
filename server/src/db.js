const nconf = require('nconf');

const conf = nconf.get('db');
const pg = require('pg');

const pool = new pg.Pool(conf);
module.exports = pool;
