require('dotenv').config()

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')


const app = express();
const routes = require('./routes');

app.use(express.json())

app.use('/', routes)

const PORT = process.env.PORT || 3000


// Credenciais
const DB_USER = process.env.DB_USER
const DB_PASSWORD = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${DB_USER}:${DB_PASSWORD}@cluster0.xrdfw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  }); 
}).catch((err) => console.log(err))

