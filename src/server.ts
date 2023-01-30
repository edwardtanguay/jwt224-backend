import express from 'express';
import cors from 'cors';
import * as model from './model.js';
import dotenv from 'dotenv';
import * as config from './config.js';
import jwt from 'jsonwebtoken';

dotenv.config();

interface CustomRequest extends Request {
	token: string;
}

const decodeJwt = (token: string) => {
	let base64Url = token.split('.')[1];
	let base64 = base64Url.replace('-', '+').replace('_', '/');
	let decodedData = JSON.parse(Buffer.from(base64, 'base64').toString('binary'));
	return decodedData;
}

const verifyToken = (req: express.Request, res: express.Response, next: express.NextFunction) => {
	const bearerHeader = req.headers['authorization'];
	if (typeof bearerHeader !== 'undefined') {
		const bearer = bearerHeader.split(' ');
		const bearerToken = bearer[1];
		(req as unknown as CustomRequest).token = bearerToken;
		next();
	} else {
		res.sendStatus(403);
	}
};

const app = express();
app.use(cors({
	origin: ['http://localhost:3611'],
	methods: ['POST', 'PUT', 'GET', 'OPTIONS', 'HEAD'],
	credentials: true
}));
app.use(express.json());
const port = config.port;

app.get('/', (req: express.Request, res: express.Response) => {
	res.send(model.getApiInstructions());
});

app.get('/welcomemessage', (req: express.Request, res: express.Response) => {
	res.send(model.getWelcomeMessage());
})

// TODO: fix since hacker can enter with any token
app.post('/welcomemessage', verifyToken, (req: express.Request, res: express.Response) => {
	const { welcomeMessage } = req.body;
	model.saveWelcomeMessage(welcomeMessage);
	res.send({});
})

app.post('/login', (req: express.Request, res: express.Response) => {
	const password = req.body.password;
	if (password === process.env.ADMIN_PASSWORD) {
		const user = {
			firstName: 'Admin',
			lastName: 'User',
			accessGroups: [
				'loggedInUsers', 'admins'
			]
		}
		jwt.sign({ user }, process.env.SESSION_SECRET, { expiresIn: config.secondsTillTimeout + 's' }, (err: any, token: any) => {
			res.json({
				user,
				token
			});
		})
	} else {
		res.status(401).send({});
	}
});

app.post('/currentuser', verifyToken, (req: express.Request, res: express.Response) => {
    jwt.verify((req as unknown as CustomRequest).token, process.env.SESSION_SECRET, (err) => {
        if (err) {
            res.sendStatus(403);
        } else {
            const data = decodeJwt((req as unknown as CustomRequest).token);
            res.json({
                user: data.user
            });
        }
    });
});

app.listen(port, () => {
	console.log(`listening on port http://localhost:${port}`);
});