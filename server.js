const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");

dotenv.config();
connectDB();

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req,res) => {
    res.send("API RUNNING......");
});

app.use("/api/auth",authRoutes);

const PORT = process.env.PORT || 5001;

app.listen(PORT, () => {
    // console.log("Server Started at http://localhost:"+PORT);
    console.log(`Server Started at http://localhost:${PORT}`);
});