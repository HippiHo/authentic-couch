const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// set up a mongoose model
module.exports = mongoose.model('User', new Schema({ 
  name: String, 
  password: String, 
  admin: Boolean 
  
  // TODO 6 the user needs two values for getting verified. A token holder and a verified flag
  // example   
  // verificationToken: {
  //   type: String,
  //   default: null
  // },
  // verifiedAt: Date

}));
