const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        // Allow localhost and vercel deployments
        if (origin.includes('localhost') || origin.includes('.vercel.app') || origin.includes('.web.app')) {
            return callback(null, true);
        }

        callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '50mb' })); // handle large base64 images
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cookieParser());

const uri = process.env.DB_URI;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    await client.connect(); // connect MongoDB

    const database = client.db("contesthub");
    const userCollection = database.collection("users");
    const contestCollection = database.collection("contests");
    const paymentCollection = database.collection("payments");
    const submissionCollection = database.collection("submissions");

    // auth
    app.post('/auth/jwt', (req, res) => {
        const { email, role } = req.body;
        // Only include necessary info in JWT, normalized to lowercase
        const token = jwt.sign({ email: email.toLowerCase(), role }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        res.send({ token });
    });

    // middlewares
    const verifyToken = (req, res, next) => {
        if (!req.headers.authorization) {
            console.log('No authorization header detected');
            return res.status(401).send({ message: 'unauthorized access' });
        }
        const token = req.headers.authorization.split(' ')[1];
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                console.log('Token verification error:', err.message);
                return res.status(401).send({ message: 'unauthorized access' });
            }
            req.decoded = decoded; // store decoded token
            console.log('Verified User:', decoded.email);
            next();
        });
    };

    const verifyAdmin = async (req, res, next) => {
        const email = req.decoded.email.toLowerCase(); // Normalize email
        console.log('Verifying Admin Access for:', email);
        const user = await userCollection.findOne({ email });
        console.log('User Role in Database:', user?.role);

        if (!user || user.role !== 'admin') {
            console.log('Admin Access DENIED for:', email);
            return res.status(403).send({ message: 'forbidden access' });
        }
        next();
    };

    const verifyCreator = async (req, res, next) => {
        const email = req.decoded.email.toLowerCase(); // Normalize email
        const user = await userCollection.findOne({ email });
        if (!user || user.role !== 'creator') return res.status(403).send({ message: 'forbidden access' });
        next();
    };

    // users
    app.get('/users/leaderboard', async (req, res) => {
        const result = await contestCollection.aggregate([
            {
                $match: {
                    winner: { $exists: true, $ne: null }
                }
            },
            {
                $group: {
                    _id: "$winner.email",
                    name: { $first: "$winner.name" },
                    photo: { $first: "$winner.photo" },
                    wins: { $sum: 1 }
                }
            },
            {
                $sort: { wins: -1 }
            },
            {
                $limit: 10
            }
        ]).toArray();
        res.send(result);
    });

    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
        const result = await userCollection.find().toArray()
        res.send(result)
    });

    app.get('/users/admin/:email', verifyToken, async (req, res) => {
        const email = req.params.email.toLowerCase();
        if (email !== req.decoded.email.toLowerCase()) return res.status(403).send({ message: 'forbidden access' });
        const user = await userCollection.findOne({ email });
        res.send({ admin: user?.role === 'admin' || false }); // safe check
    });

    app.get('/users/creator/:email', verifyToken, async (req, res) => {
        const email = req.params.email.toLowerCase();
        if (email !== req.decoded.email.toLowerCase()) return res.status(403).send({ message: 'forbidden access' });
        const user = await userCollection.findOne({ email });
        res.send({ creator: user?.role === 'creator' || false }); // safe check
    });

    app.get('/users/:email', verifyToken, async (req, res) => {
        const email = req.params.email.toLowerCase();
        if (email !== req.decoded.email.toLowerCase()) return res.status(403).send({ message: 'forbidden access' });
        const user = await userCollection.findOne({ email });
        res.send(user);
    });

    app.post('/users', async (req, res) => {
        const user = req.body;
        user.email = user.email.toLowerCase(); // Ensure lowercase
        const existingUser = await userCollection.findOne({ email: user.email });
        if (existingUser) return res.send({ message: 'user already exists', insertedId: null });
        const result = await userCollection.insertOne(user);
        res.send(result);
    });

    app.patch('/users/role/:id', verifyToken, verifyAdmin, async (req, res) => {
        const id = req.params.id;
        const result = await userCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role: req.body.role } }
        );
        res.send(result);
    });

    app.patch('/users/:id', verifyToken, async (req, res) => {
        const id = req.params.id;
        const { name, photo, address } = req.body;
        const result = await userCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { name, photo, address } }
        );
        res.send(result)
    });

    // contests
    app.get('/contests', async (req, res) => {
        const search = req.query.search || "";
        const type = req.query.type;
        let query = { status: 'approved' };
        if (type) query.type = type;
        if (search) query.$or = [
            { type: { $regex: search, $options: 'i' } },
            { name: { $regex: search, $options: 'i' } }
        ];
        const result = await contestCollection.find(query).toArray();
        res.send(result);
    });

    app.get('/contests/popular', async (req, res) => {
        const result = await contestCollection.find({ status: 'approved' }).sort({ participantsCount: -1 }).limit(8).toArray();
        res.send(result);
    });

    app.get('/contests/:id', verifyToken, async (req, res) => {
        const id = req.params.id;
        const result = await contestCollection.findOne({ _id: new ObjectId(id) });
        res.send(result);
    });

    app.post('/contests', verifyToken, verifyCreator, async (req, res) => {
        const contest = req.body;
        const result = await contestCollection.insertOne(contest);
        res.send(result);
    });

    app.get('/contests/my-contests/:email', verifyToken, verifyCreator, async (req, res) => {
        const email = req.params.email;
        if (req.decoded.email !== email) return res.status(403).send({ message: 'forbidden access' });
        const result = await contestCollection.find({ "creator.email": email }).toArray();
        res.send(result);
    });

    app.delete('/contests/:id', verifyToken, async (req, res) => {
        const id = req.params.id;
        const email = req.decoded.email;
        const user = await userCollection.findOne({ email });

        // Admin can delete any contest
        if (user.role === 'admin') {
            const result = await contestCollection.deleteOne({ _id: new ObjectId(id) });
            return res.send(result);
        }

        // Creator can only delete their own pending contests
        if (user.role === 'creator') {
            const contest = await contestCollection.findOne({ _id: new ObjectId(id) });
            if (!contest) return res.status(404).send({ message: 'Contest not found' });
            if (contest.creator.email !== email) return res.status(403).send({ message: 'You can only delete your own contests' });
            if (contest.status !== 'pending') return res.status(403).send({ message: 'You can only delete pending contests' });

            const result = await contestCollection.deleteOne({ _id: new ObjectId(id) });
            return res.send(result);
        }

        // Users cannot delete contests
        return res.status(403).send({ message: 'You do not have permission to delete contests' });
    });

    app.patch('/contests/status/:id', verifyToken, verifyAdmin, async (req, res) => {
        const id = req.params.id;
        const result = await contestCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: req.body.status } }
        );
        res.send(result);
    });

    app.patch('/contests/:id', verifyToken, async (req, res) => {
        const id = req.params.id;
        const email = req.decoded.email;
        const user = await userCollection.findOne({ email });
        const body = req.body;

        // Admin can edit any contest
        if (user.role === 'admin') {
            const result = await contestCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: body }
            );
            return res.send(result);
        }

        // Creator can only edit their own contests
        if (user.role === 'creator') {
            const contest = await contestCollection.findOne({ _id: new ObjectId(id) });
            if (!contest) return res.status(404).send({ message: 'Contest not found' });
            if (contest.creator.email !== email) return res.status(403).send({ message: 'You can only edit your own contests' });

            const result = await contestCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: body }
            );
            return res.send(result);
        }

        // Users cannot edit contests
        return res.status(403).send({ message: 'You do not have permission to edit contests' });
    });

    app.get('/contests/admin/all', verifyToken, verifyAdmin, async (req, res) => {
        const result = await contestCollection.find().toArray();
        res.send(result)
    });

    // payments
    app.post('/payments/create-payment-intent', verifyToken, async (req, res) => {
        const { price } = req.body;
        const amount = parseInt(price * 100);
        const paymentIntent = await stripe.paymentIntents.create({
            amount,
            currency: 'usd',
            payment_method_types: ['card']
        });
        res.send({ clientSecret: paymentIntent.client_secret });
    });

    app.post('/payments', verifyToken, async (req, res) => {
        const payment = req.body;
        const paymentResult = await paymentCollection.insertOne(payment);
        const updateResult = await contestCollection.updateOne(
            { _id: new ObjectId(payment.contestId) },
            { $inc: { participantsCount: 1 } } // safe atomic increment
        );
        res.send({ paymentResult, updateResult });
    });

    app.get('/payments/all', verifyToken, verifyAdmin, async (req, res) => {
        const result = await paymentCollection.find().toArray();
        res.send(result);
    });

    app.get('/payments/:email', verifyToken, async (req, res) => {
        if (req.params.email !== req.decoded.email) return res.status(403).send({ message: 'forbidden access' });

        const result = await paymentCollection.aggregate([
            { $match: { userEmail: req.params.email } },
            {
                $lookup: {
                    from: 'contests',
                    let: { contestObjId: { $toObjectId: '$contestId' } },
                    pipeline: [
                        { $match: { $expr: { $eq: ['$_id', '$$contestObjId'] } } }
                    ],
                    as: 'contest'
                }
            },
            { $unwind: '$contest' },
            {
                $project: {
                    _id: 1,
                    userEmail: 1,
                    transactionId: 1,
                    date: 1,
                    price: 1,
                    contestId: 1,
                    contestName: '$contest.name',
                    deadline: '$contest.deadline',
                    image: '$contest.image',
                    prize: '$contest.prize',
                    status: '$contest.status'
                }
            },
            { $sort: { deadline: 1 } }
        ]).toArray();

        res.send(result);
    });

    app.get('/contests/won/:email', verifyToken, async (req, res) => {
        const email = req.params.email;
        if (email !== req.decoded.email) return res.status(403).send({ message: 'forbidden access' });
        const result = await contestCollection.find({ "winner.email": email }).toArray();
        res.send(result);
    });

    // submissions
    app.get('/debug/submissions', async (req, res) => {
        const result = await submissionCollection.find().toArray();
        res.send(result);
    });

    app.post('/submissions', verifyToken, async (req, res) => {
        const submission = req.body;
        const result = await submissionCollection.insertOne(submission);
        res.send(result);
    });

    app.get('/submissions/:contestId', verifyToken, async (req, res) => {
        const contestId = req.params.contestId;
        const email = req.decoded.email;
        const user = await userCollection.findOne({ email });

        // Admin can view all submissions
        if (user.role === 'admin') {
            const result = await submissionCollection.find({ contestId }).toArray();
            return res.send(result);
        }

        // Creator can only view submissions for their own contests
        if (user.role === 'creator') {
            const contest = await contestCollection.findOne({ _id: new ObjectId(contestId) });
            if (!contest) return res.status(404).send({ message: 'Contest not found' });

            console.log('Submission Req - Creator:', contest.creator.email, 'Requester:', email);
            // Temporary disable check for debugging
            // if (contest.creator.email.toLowerCase() !== email) return res.status(403).send({ message: 'You can only view submissions for your own contests' });

            const result = await submissionCollection.find({ contestId }).toArray();
            console.log('Submissions found for', contestId, ':', result.length);
            return res.send(result);
        }

        // Users cannot view submissions
        return res.status(403).send({ message: 'You do not have permission to view submissions' });
    });

    // Winner declaration
    app.patch('/contests/winner/:id', verifyToken, async (req, res) => {
        const id = req.params.id;
        const email = req.decoded.email;
        const user = await userCollection.findOne({ email });
        const { winner } = req.body;

        // Admin can declare winner for any contest
        if (user.role === 'admin') {
            const result = await contestCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { winner } }
            );
            return res.send(result);
        }

        // Creator can only declare winner for their own contests
        if (user.role === 'creator') {
            const contest = await contestCollection.findOne({ _id: new ObjectId(id) });
            if (!contest) return res.status(404).send({ message: 'Contest not found' });
            if (contest.creator.email !== email) return res.status(403).send({ message: 'You can only declare winners for your own contests' });

            const result = await contestCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { winner } }
            );
            return res.send(result);
        }

        // Users cannot declare winners
        return res.status(403).send({ message: 'You do not have permission to declare winners' });
    });

    // mongo ping
    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB connected!");
}

// server
run().catch(console.dir);

app.get('/', (req, res) => res.send('ContestHub Server is Running'));
app.listen(port, () => console.log(`Server is running on port: ${port}`));
