import express from "express";
import {updateUser , deleteUser, getAllUsers , getSingleUser,getUserProfile, getMyAppointments} from "../Controllers/userController.js"
import { authentication, restrict } from "../auth/verifyToken.js";

const router = express.Router();

router.get("/:id", authentication, getSingleUser);
router.get("/", authentication, getAllUsers);
router.post("/:id",authentication, restrict(['patient']), updateUser);
router.delete("/:id",authentication, restrict(['patient']), deleteUser);
router.get("/profile/me", authentication, restrict(["patient"]), getUserProfile);
router.get("/appointments/my-appointments", authentication, restrict(["patient"]), getMyAppointments);


export default router;


