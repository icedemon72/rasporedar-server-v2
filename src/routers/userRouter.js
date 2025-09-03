import express from 'express';
import { getUserFromSession, handleLoginUser, handleLogout } from '../controllers/sessionController.js';
import { handleEditUser, handleGetUserById, handleGetUserInstitutions, handleUserRegister } from '../controllers/userController.js';
import authenticate from '../middleware/authenticate.js';
import { validateUserEdit, validateUserRegister } from '../validators/userValidator.js';


const router = express.Router({ mergeParams: true });

router.post('/login', handleLoginUser);

router.post('/logout', handleLogout);

router.post(
	'/register', 
	validateUserRegister,
	handleUserRegister
);

router.patch(
	'/users/edit',
	authenticate,
	validateUserEdit,
	handleEditUser
);

router.get(['/users', '/users/:id'], authenticate, handleGetUserById);

router.get(['/user_institutions/', '/user_institutions/:id'], authenticate, handleGetUserInstitutions);

router.get(
	'/me',
	authenticate,
	getUserFromSession
);

export { router as userRouter };