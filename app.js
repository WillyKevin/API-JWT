//Imports
require ('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

//Config JSON Response
app.use(express.json()); //da acesso a todas as rotas, (exceto se eu usar o middleware)

//Models
const User = require('./models/User');

//Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem Vindo a nossa API :p"});
});

//Private Route
app.get('/user/:id', checkToken, async (req, res) => { //Middleware checkToken para validar esta rota especifica
    const id = req.params.id;

    //Check User if Exists
    const user = await User.findById(id, '-password') // filtro pra excluir a senha do User do retorno 

    if (!user) {
        res.status(404).json({msg: 'Usuário não encontrado'})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization'] //Pegar o token por autorizaçao
    const token = authHeader && authHeader.split(" ")[1] //Se o token vir a gente separa ele e transforma em um array

    if (!token) {
        res.status(401).json({msg: "Acesso negado"})
    }

    //Validar se o Token é correto
    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)
        
        next()

    } catch (error) {
        res.status(400).json({msg: "Token inválido"})
    }
}

//Register User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    //Validations
    if (!name) {
        res.status(422).json({msg: "O nome é obrigatório!"});
    }

    if (!email) {
        res.status(422).json({msg: "O email é obrigatório!"});
    }

    if (!password) {
        res.status(422).json({msg: "A senha é obrigatória!"});
    }

    if (password !== confirmpassword) {
        res.status(422).json({msg: "As senhas não conferem!"});
    }

    //Check if User exist
    const userExists = await User.findOne({ email: email });

    if (userExists) {
        res.status(422).json({msg: "Por Favor, Ultiliza outro email!"});
    }

    //Create Password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //Create User
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save();
        res.status(201).json({msg: "Usuário criado com sucesso!"})

    } catch (error) {
        console.log(error)
        res.status(500).json({msg: "Aconteceu um erro no servidor, tente novamente mais tarde!"});
    }
})

//Login User
app.post('/auth/login', async (req, res) => {

    const {email, password} = req.body

    //Validations
    if (!email) {
        res.status(422).json({msg: "O email é obrigatório!"})
    }

    if (!password) {
        res.status(422).json({msg: "A senha é obrigatória!"})
    }

    //Check if User Exists
    const user = await User.findOne({ email: email })

    if (!user) {
        res.status(404).json({msg: "Usuário não encontrado!"})
    }

    //Check if Password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        res.status(422).json({msg: "Senha Inválida!"})
    }

    try {

        const secret = process.env.SECRET //Secret que será mandado junto ao token para validaçao do token
        
        const token = jwt.sign(
        {
            id: user._id
        }, 
        secret, 
    )

        res.status(200).json({msg: "Autenticação realizada com sucesso!", token})
    } catch (err) {
        console.log(error)
        res.status(500).json({msg: "Aconteceu um erro no servidor, tente novamente mais tarde!"})
    }

});


//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

//Conexão com o banco
mongoose
  .connect(`mongodb+srv://${dbUser}:${dbPassword}@jwtcluster.kzlwiz6.mongodb.net/?retryWrites=true&w=majority`)
  .then(() => {
    app.listen(3000); // Aplicação ira rodar nesta porta junto com a inicialização do banco, o banco inicia, em seguida aplicação
    console.log("Conectou ao MongoDB!");
}).catch((err) => console.log(err));



