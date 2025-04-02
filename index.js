require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const path = require('path');
const cors = require('cors');

// Initialize express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
let client;
let db;

async function connectToMongoDB() {
    try {
        console.log('Attempting to connect to MongoDB...');
        
        // Connect to MongoDB Atlas
        client = await MongoClient.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log('Connected to MongoDB Atlas');
        
        // Get database reference
        db = client.db('mongodbVSCodePlaygroundDB');
        
        // Test the connection
        await db.command({ ping: 1 });
        console.log('Database connection test successful');
        
        // Create indexes if they don't exist
        await db.collection('users').createIndex({ username: 1 }, { unique: true });
        console.log('Database indexes created/verified');
        
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1); // Exit if we can't connect to the database
    }
}

// Connect to MongoDB when the server starts
connectToMongoDB();

// Middleware to check database connection
app.use((req, res, next) => {
    if (!db) {
        return res.status(500).json({
            success: false,
            message: 'Database connection not established'
        });
    }
    next();
});

// Routes

// API Routes

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Input validation
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Find user
        const user = await db.collection('users').findOne({ username });
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Check if user is active
        if (user.status !== 'active') {
            return res.status(401).json({
                success: false,
                message: 'Account is inactive'
            });
        }

        // Check password (in a real application, you should use proper password hashing)
        if (user.password !== password) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // Update last login
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );

        // Remove password from user object before sending
        const { password: _, ...userWithoutPassword } = user;

        res.json({
            success: true,
            message: 'Login successful',
            user: userWithoutPassword,
            redirectUrl: user.isAdmin ? '/admin.html' : '/dashboard.html'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error during login',
            error: error.message
        });
    }
});

// Create a new user
app.post('/api/users', async (req, res) => {
    try {
        console.log('Received user registration request');
        const { username, password, isAdmin } = req.body;

        // Input validation
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Validate username format (alphanumeric, 3-20 characters)
        if (!/^[a-zA-Z0-9]{3,20}$/.test(username)) {
            return res.status(400).json({
                success: false,
                message: 'Username must be 3-20 characters long and contain only letters and numbers'
            });
        }

        // Validate password (at least 6 characters)
        if (password.length < 3) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        // Check if username already exists
        const existingUser = await db.collection('users').findOne({ username });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Username already exists'
            });
        }

        // Create new user
        const result = await db.collection('users').insertOne({
            username,
            password, // In a real application, you should hash the password
            createdAt: new Date(),
            lastLogin: null,
            status: 'active',
            isAdmin: isAdmin || false
        });


        console.log('User created successfully:', result.insertedId);
        
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            userId: result.insertedId
        });

    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating user',
            error: error.message
        });
    }
});

// Update user
app.put('/api/users/:id', async (req, res) => {
    try {
        const { username, password, status } = req.body;
        const userId = new ObjectId(req.params.id);

        // Validate input
        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }

        // Check if username is already taken by another user
        const existingUser = await db.collection('users').findOne({
            username,
            _id: { $ne: userId }
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Username already exists'
            });
        }

        // Prepare update object
        const updateObj = {
            username,
            status: status || 'active'
        };

        // Only update password if provided
        if (password) {
            if (password.length < 6) {
                return res.status(400).json({
                    success: false,
                    message: 'Password must be at least 6 characters long'
                });
            }
            updateObj.password = password;
        }

        // Update user
        const result = await db.collection('users').updateOne(
            { _id: userId },
            { $set: updateObj }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'User updated successfully'
        });

    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating user',
            error: error.message
        });
    }
});

// Delete user
app.delete('/api/users/:id', async (req, res) => {
    try {
        const userId = new ObjectId(req.params.id);

        // Check if user exists
        const user = await db.collection('users').findOne({ _id: userId });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent deleting the last admin user
        if (user.isAdmin) {
            const adminCount = await db.collection('users').countDocuments({ isAdmin: true });
            if (adminCount <= 1) {
                return res.status(400).json({
                    success: false,
                    message: 'Cannot delete the last admin user'
                });
            }
        }

        // Delete user
        const result = await db.collection('users').deleteOne({ _id: userId });

        res.json({
            success: true,
            message: 'User deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting user',
            error: error.message
        });
    }
});

// Get all users (for testing purposes)
app.get('/api/users', async (req, res) => {
    try {
        console.log('Fetching users from database...');
        
        // Check if database connection exists
        if (!db) {
            console.error('Database connection not established');
            return res.status(500).json({
                success: false,
                message: 'Database connection not established'
            });
        }

        // Get users collection
        const usersCollection = db.collection('users');
        console.log('Users collection accessed');

        // Find all users
        const users = await usersCollection
            .find({}, { projection: { password: 0 } }) // Exclude password from results
            .toArray();

        console.log(`Successfully fetched ${users.length} users`);

        res.json({
            success: true,
            users: users
        });
    } catch (error) {
        console.error('Error in /api/users endpoint:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching users',
            error: error.message
        });
    }
});

// Get user by ID
app.get('/api/users/:id', async (req, res) => {
    try {
        const user = await db.collection('users')
            .findOne(
                { _id: new ObjectId(req.params.id) },
                { projection: { password: 0 } }
            );

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            user: user
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching user',
            error: error.message
        });
    }
});

// Get all categories
app.get('/api/categories', async (req, res) => {
    try {
        const categories = await db.collection('categories')
            .find({})
            .sort({ name: 1 })
            .toArray();

        res.json({
            success: true,
            categories: categories
        });
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching categories',
            error: error.message
        });
    }
});

// Create a new category
app.post('/api/categories', async (req, res) => {
    try {
        const { name, incentivePercentage } = req.body;

        // Input validation
        if (!name || incentivePercentage === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Category name and incentive percentage are required'
            });
        }

        // Validate incentive percentage
        if (isNaN(incentivePercentage) || incentivePercentage < 0 || incentivePercentage > 100) {
            return res.status(400).json({
                success: false,
                message: 'Incentive percentage must be between 0 and 100'
            });
        }

        // Check if category already exists
        const existingCategory = await db.collection('categories').findOne({ name });
        if (existingCategory) {
            return res.status(400).json({
                success: false,
                message: 'Category already exists'
            });
        }

        const result = await db.collection('categories').insertOne({
            name,
            incentivePercentage: parseFloat(incentivePercentage),
            createdAt: new Date()
        });

        res.status(201).json({
            success: true,
            message: 'Category created successfully',
            categoryId: result.insertedId
        });
    } catch (error) {
        console.error('Error creating category:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating category',
            error: error.message
        });
    }
});

// Delete category
app.delete('/api/categories/:id', async (req, res) => {
    try {
        const categoryId = new ObjectId(req.params.id);

        // Check if category exists
        const category = await db.collection('categories').findOne({ _id: categoryId });
        if (!category) {
            return res.status(404).json({
                success: false,
                message: 'Category not found'
            });
        }

        // Check if category is being used by any products
        const productsWithCategory = await db.collection('products').findOne({ categoryId: categoryId });
        if (productsWithCategory) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete category that has associated products'
            });
        }

        // Delete category
        const result = await db.collection('categories').deleteOne({ _id: categoryId });

        res.json({
            success: true,
            message: 'Category deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting category:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting category',
            error: error.message
        });
    }
});

// Get product by ID
app.get('/api/products', async (req, res) => {
    try {
        const products = await db.collection('products')
            .aggregate([
                {
                    $lookup: {
                        from: 'categories',
                        localField: 'categoryId',
                        foreignField: '_id',
                        as: 'category'
                    }
                },
                {
                    $unwind: {
                        path: '$category',
                        preserveNullAndEmptyArrays: true
                    }
                }
            ]).toArray();

        res.json({
            success: true,
            products: products
        });
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching products',
            error: error.message
        });
    }
});

// Get product by ID
app.get('/api/products/:id', async (req, res) => {
    try {
        const productId = new ObjectId(req.params.id);
        
        const product = await db.collection('products')
            .aggregate([
                {
                    $match: { _id: productId }
                },
                {
                    $lookup: {
                        from: 'categories',
                        localField: 'categoryId',
                        foreignField: '_id',
                        as: 'category'
                    }
                },
                {
                    $unwind: {
                        path: '$category',
                        preserveNullAndEmptyArrays: true
                    }
                }
            ]).toArray();

        if (!product || product.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        res.json({
            success: true,
            product: product[0]
        });

    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching product',
            error: error.message
        });
    }
});

// Create a new product
app.post('/api/products', async (req, res) => {
    try {
        const { name, netCost, categoryId } = req.body;

        // Input validation
        if (!name || netCost === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Product name and net cost are required'
            });
        }

        // Validate net cost is a positive number
        if (isNaN(netCost) || netCost <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Net cost must be a positive number'
            });
        }

        // Create new product
        const productData = {
            name,
            netCost: parseFloat(netCost),
            createdAt: new Date()
        };

        // Add categoryId if provided
        if (categoryId) {
            productData.categoryId = new ObjectId(categoryId);
        }

        const result = await db.collection('products').insertOne(productData);

        res.status(201).json({
            success: true,
            message: 'Product created successfully',
            productId: result.insertedId
        });

    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating product',
            error: error.message
        });
    }
});

// Update product
app.put('/api/products/:id', async (req, res) => {
    try {
        const { name, netCost } = req.body;
        const productId = new ObjectId(req.params.id);

        // Input validation
        if (!name || netCost === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Product name and net cost are required'
            });
        }

        // Validate net cost is a positive number
        if (isNaN(netCost) || netCost <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Net cost must be a positive number'
            });
        }

        // Update product
        const result = await db.collection('products').updateOne(
            { _id: productId },
            { $set: { name, netCost: parseFloat(netCost) } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        res.json({
            success: true,
            message: 'Product updated successfully'
        });

    } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating product',
            error: error.message
        });
    }
});

// Delete product
app.delete('/api/products/:id', async (req, res) => {
    try {
        const productId = new ObjectId(req.params.id);

        // Delete product
        const result = await db.collection('products').deleteOne({ _id: productId });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        res.json({
            success: true,
            message: 'Product deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting product',
            error: error.message
        });
    }
});

// Calculate incentive
app.post('/api/calculate-incentive', async (req, res) => {
    try {
        const { date, sales } = req.body;

        // Input validation
        if (!date || !sales || !Array.isArray(sales) || sales.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Date and sales data are required'
            });
        }

        // Get all products and users involved in the sales
        const productIds = sales.map(sale => new ObjectId(sale.productId));
        const userIds = sales.map(sale => new ObjectId(sale.userId));

        const [products, users] = await Promise.all([
            db.collection('products')
                .aggregate([
                    {
                        $lookup: {
                            from: 'categories',
                            localField: 'categoryId',
                            foreignField: '_id',
                            as: 'category'
                        }
                    },
                    {
                        $unwind: {
                            path: '$category',
                            preserveNullAndEmptyArrays: true
                        }
                    }
                ])
                .toArray(),
            db.collection('users').find({ _id: { $in: userIds } }).toArray()
        ]);

        // Create a map of products and users for easy lookup
        const productMap = new Map(products.map(p => [p._id.toString(), p]));
        const userMap = new Map(users.map(u => [u._id.toString(), u]));

        // Calculate incentive for each sale
        const incentiveDetails = sales.map(sale => {
            const product = productMap.get(sale.productId);
            const user = userMap.get(sale.userId);

            if (!product || !user) {
                throw new Error(`Product or user not found for sale: ${sale.productId}`);
            }

            const profit = sale.price - product.netCost;
            // Use category-specific incentive percentage or default to 10%
            const incentivePercentage = product.category ? product.category.incentivePercentage : 10;
            const incentive = profit * (incentivePercentage / 100);

            return {
                productName: product.name,
                categoryName: product.category ? product.category.name : 'Uncategorized',
                userName: user.username,
                userId: user._id.toString(),
                salePrice: sale.price,
                netCost: product.netCost,
                profit: profit,
                incentivePercentage: incentivePercentage,
                incentive: incentive
            };
        });

        // Calculate total incentive and user-wise incentives
        const totalIncentive = incentiveDetails.reduce((sum, detail) => sum + detail.incentive, 0);
        const userIncentives = incentiveDetails.reduce((acc, detail) => {
            if (!acc[detail.userId]) {
                acc[detail.userId] = {
                    userId: detail.userId,
                    userName: detail.userName,
                    totalIncentive: 0,
                    sales: []
                };
            }
            acc[detail.userId].totalIncentive += detail.incentive;
            acc[detail.userId].sales.push(detail);
            return acc;
        }, {});

        // Save the incentive calculation to the database
        await db.collection('incentives').insertOne({
            date: new Date(date),
            sales: sales,
            details: incentiveDetails,
            totalIncentive: totalIncentive,
            userIncentives: Object.values(userIncentives),
            createdAt: new Date()
        });

        res.json({
            success: true,
            message: 'Incentive calculated successfully',
            incentive: {
                date: date,
                details: incentiveDetails,
                totalIncentive: totalIncentive,
                userIncentives: Object.values(userIncentives)
            }
        });

    } catch (error) {
        console.error('Error calculating incentive:', error);
        res.status(500).json({
            success: false,
            message: 'Error calculating incentive',
            error: error.message
        });
    }
});

// Get user incentives
app.get('/api/user-incentives', async (req, res) => {
    try {
        console.log('Fetching user incentives...');
        const { year, month } = req.query;
        
        let query = {};
        
        // Add date filtering if year and month are provided
        if (year && month) {
            const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
            const endDate = new Date(parseInt(year), parseInt(month), 0); // Last day of the month
            query.date = {
                $gte: startDate,
                $lte: endDate
            };
        }
        
        const incentives = await db.collection('incentives')
            .find(query)
            .sort({ date: -1 })
            .toArray();

        console.log(`Found ${incentives.length} incentive records`);

        // Calculate total incentives for each user
        const userTotals = {};
        
        // Process each incentive record
        incentives.forEach(inc => {
            // Skip if userIncentives is undefined or not an array
            if (!inc.userIncentives || !Array.isArray(inc.userIncentives)) {
                console.log('Skipping invalid incentive record:', inc);
                return;
            }

            // Process each user's incentives in this record
            inc.userIncentives.forEach(userInc => {
                if (!userTotals[userInc.userId]) {
                    userTotals[userInc.userId] = {
                        userId: userInc.userId,
                        userName: userInc.userName,
                        totalIncentive: 0,
                        sales: []
                    };
                }
                userTotals[userInc.userId].totalIncentive += userInc.totalIncentive;
                userTotals[userInc.userId].sales.push(...userInc.sales);
            });
        });

        // Get credited amounts for all users
        const users = await db.collection('users').find({}).toArray();
        const userCredits = new Map(users.map(user => [user._id.toString(), user.totalCredited || 0]));

        // Add credited amounts to user totals
        Object.values(userTotals).forEach(userTotal => {
            userTotal.totalCredited = userCredits.get(userTotal.userId) || 0;
        });

        console.log(`Processed incentives for ${Object.keys(userTotals).length} users`);

        res.json({
            success: true,
            userIncentives: Object.values(userTotals)
        });
    } catch (error) {
        console.error('Error fetching user incentives:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching user incentives',
            error: error.message
        });
    }
});

// Get all incentives (sales history)
app.get('/api/incentives', async (req, res) => {
    try {
        console.log('Fetching all incentives...');
        const { year, month } = req.query;
        
        let query = {};
        
        // Add date filtering if year and month are provided
        if (year && month) {
            const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
            const endDate = new Date(parseInt(year), parseInt(month), 0); // Last day of the month
            query.date = {
                $gte: startDate,
                $lte: endDate
            };
        }
        
        const incentives = await db.collection('incentives')
            .find(query)
            .sort({ date: -1 })
            .toArray();

        console.log(`Successfully fetched ${incentives.length} incentive records`);

        res.json({
            success: true,
            incentives: incentives
        });
    } catch (error) {
        console.error('Error fetching incentives:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching incentives',
            error: error.message
        });
    }
});

// Delete incentive (sale)
app.delete('/api/incentives/:id', async (req, res) => {
    try {
        const incentiveId = new ObjectId(req.params.id);

        // Check if incentive exists
        const incentive = await db.collection('incentives').findOne({ _id: incentiveId });
        if (!incentive) {
            return res.status(404).json({
                success: false,
                message: 'Sale record not found'
            });
        }

        // Delete the entire incentive record
        const result = await db.collection('incentives').deleteOne({ _id: incentiveId });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Sale record not found'
            });
        }

        res.json({
            success: true,
            message: 'Sale deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting sale:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting sale',
            error: error.message
        });
    }
});

// Credit incentive to user
app.post('/api/credit-incentive', async (req, res) => {
    try {
        const { userId, amount } = req.body;

        // Input validation
        if (!userId || amount === undefined) {
            return res.status(400).json({
                success: false,
                message: 'User ID and amount are required'
            });
        }

        // Validate amount is a positive number
        if (isNaN(amount) || amount <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Amount must be a positive number'
            });
        }

        // Get user's current incentive data
        const userIncentives = await db.collection('incentives')
            .find({})
            .sort({ date: -1 })
            .toArray();

        // Calculate total earned and credited
        let totalEarned = 0;
        let totalCredited = 0;

        userIncentives.forEach(inc => {
            if (inc.userIncentives) {
                const userInc = inc.userIncentives.find(ui => ui.userId === userId);
                if (userInc) {
                    totalEarned += userInc.totalIncentive;
                }
            }
        });

        // Get user's current credited amount
        const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        totalCredited = user.totalCredited || 0;
        const currentBalance = totalEarned - totalCredited;

        // Check if there's enough balance
        if (amount > currentBalance) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance'
            });
        }

        // Update user's credited amount
        const newTotalCredited = totalCredited + amount;
        await db.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { 
                $set: { 
                    totalCredited: newTotalCredited,
                    lastCredited: new Date()
                }
            }
        );

        // Create credit transaction record
        await db.collection('creditTransactions').insertOne({
            userId: new ObjectId(userId),
            amount: amount,
            creditedAt: new Date(),
            previousBalance: currentBalance,
            newBalance: currentBalance - amount
        });

        res.json({
            success: true,
            message: 'Incentive credited successfully',
            newBalance: currentBalance - amount,
            totalCredited: newTotalCredited
        });

    } catch (error) {
        console.error('Error crediting incentive:', error);
        res.status(500).json({
            success: false,
            message: 'Error crediting incentive',
            error: error.message
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: err.message
    });
});

// Handle 404 errors
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Access the application at http://localhost:${PORT}`);
});

// Handle graceful shutdown
process.on('SIGINT', async () => {
    try {
        if (client) {
            await client.close();
            console.log('MongoDB connection closed');
        }
        process.exit(0);
    } catch (error) {
        console.error('Error during shutdown:', error);
        process.exit(1);
    }
});