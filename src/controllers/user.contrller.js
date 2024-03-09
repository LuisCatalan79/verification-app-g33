const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require ('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email,password,firstName,lastName,country,image,frontBaseUrl}= req.body;
    const encriptedPassword = await bcrypt.hash(password,10);
    const result = await User.create({
        email,
        password:encriptedPassword,
        firstName,
        lastName,
        country,
        image
    });
    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/${code}`;

    await EmailCode.create({
        code,
        userId: result.id
    });

    await sendEmail ({
        to:email,
        subject:"Verify email for user app",
        // text:"esto es un correo desde node"
        html:`
        <h1>¡Hello ${firstName} ${lastName}!</h1>
        <p><a href="${link}">${link}</a></p>
        <p><b>Code:</b>${code}</p>
        <p><b>Thanks for sign up in user app</b></p>
        `,});
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const {email,firstName,lastName,country,image}= req.body;
    const result = await User.update(
        {email,firstName,lastName,country,image},
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyEmail = catchError (async(req,res)=>{
    const {code}=req.params;
    const emailCode = await EmailCode.findOne({
        where:{code}
    });
    if (!emailCode) return res.status(401).json({message:"Invalid code"});
    const user = await User.update(
        {isVerified:true},
        {where:{id:emailCode.userId}, returning:true}
    );
    await emailCode.destroy();
    return res.json(user[1][0]);
})

const login = catchError(async(req,res)=>{

   const { email, password } = req.body;
      const user = await User.findOne ({where: {email:email}});
      if(!user) return res.status(401).json({message:"Invalid credential"});
      if (user.isVerified === false)return res.status(401).json({message:"Unverified user"});
      const isValid = await bcrypt.compare(password, user.password);
      if(!isValid) return res.status(401).json({message:"Invalid credential"});

      const token = jwt.sign(
          { user },
          process.env.TOKEN_SECRET,
          { expiresIn: "1d" }
      );

      return res.json({user, token});
       
});

const me = catchError(async(req,res)=>{
    return res.json(req.user)
});

const emailResetPassword = catchError(async(req,res)=>{
    const { email,frontBaseUrl } = req.body;
    const user = await User.findOne ({where: {email:email}});
    if(!user) return res.status(401).json({message:"Email not found"});
    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/${code}`;

    await EmailCode.create({
        code,
        userId: user.id
    });

    await sendEmail ({
        to:email,
        subject:"Update Password",
        html:`
        <h1>¡Hello ${user.firstName} ${user.lastName}!</h1>
        <p><a href="${link}">${link}</a></p>
        <p><b>Code:</b>${code}</p>
        <p><b>Thanks for sign up in user app</b></p>
        `});
    return res.status(201).json(user);

});

const resetPassword = catchError(async(req,res)=>{
    const {password}=req.body;
    const {code}=req.params;
    const resetCode = await EmailCode.findOne({
        where:{code}
    });
    if (!resetCode) return res.status(401).json({message:"Invalid code"});
    const encriptedPassword = await bcrypt.hash(password,10);
    const user = await User.update(
        {password:encriptedPassword},
        {where:{id:resetCode.userId}, returning:true}
    );
    await resetCode.destroy();
    return res.json(user[1][0]);
})


module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    me,
    emailResetPassword,
    resetPassword
}