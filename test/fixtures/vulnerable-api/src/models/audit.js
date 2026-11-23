const { sequelize, DataTypes } = require('../db');

module.exports = sequelize.define('audit_log', {
  action: DataTypes.STRING,
  message: DataTypes.TEXT,
});
