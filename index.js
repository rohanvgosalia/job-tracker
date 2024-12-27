const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
const PORT = 4000;
const SECRET_KEY = 'your-secret-key';

app.use(cors());
app.use(express.json());

const sequelize = new Sequelize('job_tracker', 'postgres', 'Rohan@419299', {
    host: 'localhost',
    dialect: 'postgres',
    logging: false,
});

sequelize.authenticate().then(() => console.log('Connected to PostgreSQL')).catch(console.error);

const User = sequelize.define('User', {
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false },
    function: { type: DataTypes.STRING, allowNull: false }, // 'admin', 'client', 'superadmin'
    roles: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: true },
});

const Role = sequelize.define('Role', {
    name: { type: DataTypes.STRING, allowNull: false, unique: true },
});

const Job = sequelize.define('Job', {
    url: { type: DataTypes.STRING, allowNull: false },
    company: { type: DataTypes.STRING, allowNull: false },
    location: { type: DataTypes.STRING, allowNull: false },
    roles: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: true },
    status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'New' }, // New field
});


// Adjust sync logic to handle existing data
sequelize.sync({ alter: true }).then(() => console.log('Database synced!')).catch(console.error);

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ email: user.email, function: user.function, roles: user.roles }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, function: user.function, roles: user.roles });
});

const authenticate = (functions = []) => (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err || !functions.includes(user.function)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.user = user;
        next();
    });
};

app.get('/api/superadmin/users', authenticate(['superadmin']), async (req, res) => {
    try {
        const users = await User.findAll({ attributes: ['id', 'email', 'function', 'roles'] });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Error fetching users' });
    }
});

app.post('/api/superadmin/add-user', authenticate(['superadmin']), async (req, res) => {
    const { email, password, function: userFunction, roles } = req.body;
    if (!email || !password || !userFunction) return res.status(400).json({ error: 'All fields are required' });
    if (userFunction === 'client' && (!roles || roles.length === 0)) {
        return res.status(400).json({ error: 'At least one role must be assigned to a client' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ email, password: hashedPassword, function: userFunction, roles: roles || null });
        res.status(201).json({ message: 'User created successfully', user: newUser });
    } catch (err) {
        res.status(500).json({ error: 'Error creating user' });
    }
});

app.delete('/api/superadmin/delete-user/:id', authenticate(['superadmin']), async (req, res) => {
    try {
        const user = await User.findByPk(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        await user.destroy();
        res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Error deleting user' });
    }
});

app.post('/api/roles', authenticate(['superadmin', 'admin']), async (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Role name is required' });
    }

    try {
        const newRole = await Role.create({ name });
        res.status(201).json({ role: newRole });
    } catch (err) {
        if (err.name === 'SequelizeUniqueConstraintError') {
            res.status(400).json({ error: 'Role already exists' });
        } else {
            res.status(500).json({ error: 'Error adding role' });
        }
    }
});

app.delete('/api/roles/:id', authenticate(['superadmin', 'admin']), async (req, res) => {
    try {
        const role = await Role.findByPk(req.params.id);
        if (!role) return res.status(404).json({ error: 'Role not found' });
        await role.destroy();
        res.status(200).json({ message: 'Role deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Error deleting role' });
    }
});

app.get('/api/roles', authenticate(['superadmin', 'admin', 'client']), async (req, res) => {
    try {
        const roles = await Role.findAll();
        res.json(roles);
    } catch (err) {
        res.status(500).json({ error: 'Error fetching roles' });
    }
});

// Add Job Endpoint
app.post('/api/admin/add-job', authenticate(['admin']), async (req, res) => {
    const { url, company, location, roles } = req.body;

    if (!url || !company || !location || !roles || roles.length === 0) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const newJob = await Job.create({ url, company, location, roles });
        res.status(201).json({ job: newJob });
    } catch (err) {
        res.status(500).json({ error: 'Error adding job' });
    }
});

// Fetch Jobs for Client Based on Assigned Roles
app.get('/api/client/jobs', authenticate(['client']), async (req, res) => {
    try {
        const clientRoles = req.user.roles; // Get roles of the logged-in client
        if (!clientRoles || clientRoles.length === 0) {
            return res.status(200).json([]); // No roles, no jobs to display
        }

        const jobs = await Job.findAll({
            where: {
                roles: { [Sequelize.Op.overlap]: clientRoles } // Filter jobs matching any client role
            }
        });
        res.json(jobs);
    } catch (err) {
        res.status(500).json({ error: 'Error fetching jobs for client' });
    }
});

// Update Job Status Endpoint
app.patch('/api/client/jobs/:id/status', authenticate(['client']), async (req, res) => {
    const { id } = req.params; // Get job ID from the request parameters
    const { status } = req.body; // Get the new status from the request body

    // Validate status
    if (!['New', 'Applied', 'Deferred'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        // Find the job by ID
        const job = await Job.findByPk(id);
        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }

        // Update the job status
        job.status = status;
        await job.save();

        res.status(200).json({ message: 'Status updated', job });
    } catch (err) {
        res.status(500).json({ error: 'Error updating status' });
    }
});


app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
