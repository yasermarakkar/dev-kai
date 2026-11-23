const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize(process.env.DATABASE_URL, { dialectOptions: { ssl: false } });

const User = sequelize.define('users', {
  email: DataTypes.STRING,
  name: DataTypes.STRING,
  passwordHash: DataTypes.STRING,
  role: DataTypes.STRING,
});

const Order = sequelize.define('orders', {
  customerId: { type: DataTypes.INTEGER, references: { model: 'users', key: 'id' } },
  status: DataTypes.STRING,
  total: DataTypes.DECIMAL,
});

const Payment = sequelize.define('payments', {
  orderId: { type: DataTypes.INTEGER, references: { model: 'orders', key: 'id' } },
  amount: DataTypes.DECIMAL,
});

sequelize.sync({ alter: true });

module.exports = { sequelize, DataTypes, User, Order, Payment };
