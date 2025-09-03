import mongoose from 'mongoose';
import 'dotenv/config';

const connectDB = async () => {
  mongoose.set('strictQuery', true);
  try {
    mongoose.connect(process.env.DB_CONNECTION);
    console.log("Connected to MongoDB!");
  } catch (err) {
    console.log("Error while connecting to DB!");
  }

}

export default connectDB;