module.exports = function (pool, pgSessionInstance) {
  pgSessionInstance.query = (query, params = [], callback) => {
    if (!callback && typeof params === 'function') {
      callback = params
      params = []
    }
    pool.connect().then(client => {
      client.query(query, params, (err, result) => {
        client.release();
        if (err) {
          return callback(err)
        } else {
          return callback(null, (result && result.rows[0] ? true : false))
        }
      })
    })
      .catch(callback);
  }
  return pgSessionInstance;
}