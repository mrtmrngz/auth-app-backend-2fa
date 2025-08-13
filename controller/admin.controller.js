import CustomError from "../helpers/customError.js";
import User from "../models/User.model.js";
import {scheduleUnbanJob} from "../libs/schedule.js";
import {cloudinary} from "../libs/cloudinary.js";


export const admin_dashboard = async (req, res, next) => {

    try {
        const oneWeekAgo = new Date()
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7)

        /*const weekly_registration = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: oneWeekAgo }
                }
            },
            {
                $group: {
                    _id: {
                       week: {$week: "$createdAt"},
                       date: { $dayOfWeek: "$createdAt" }
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: {
                    "_id.week": 1,
                    "_id.date": 1
                }
            }
        ])
            {
                "_id": {
                  "week": 33,
                  "day": 3
                },
                "count": 8
              },
        */

        const [last_registered_users, weekly_registration, banned_users, total_user_count, verified_user_count, unverified_user_count] = await Promise.all([
            User.find().sort({createdAt: 1}).limit(10).select("email avatar username role"),
            User.aggregate([
                {
                    $match: {
                        createdAt: {$gte: oneWeekAgo},
                        isVerified: {$eq: true}
                    }
                },
                {
                    $addFields: {
                        trCreatedAt: {$add: ["$createdAt", 3 * 60 * 60 * 1000]}
                    }
                },
                {
                    $group: {
                        _id: {
                            $dateToString: {format: "%Y-%m-%d", date: "$trCreatedAt"}
                        },
                        count: {$sum: 1}
                    }
                },
                {
                    $sort: {
                        "_id": 1
                    }
                }
            ]),
            User.find({"ban_status.is_banned": true}).select("email username avatar ban_status.ban_reason ban_status.ban_expire"),
            User.countDocuments(),
            User.countDocuments({isVerified: true}),
            User.countDocuments({isVerified: false})
        ])

        res.status(200).json({
            weekly_registration: weekly_registration,
            last_ten: last_registered_users,
            banned_users,
            total_user_count,
            verified_user_count,
            unverified_user_count
        })
    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during registration.", 500));
    }
}

export const admin_user_edit = async (req, res, next) => {

    const id = req.params.id
    const uploaded_file = req.file

    const {username, email, role} = req.body

    if (!username && !email && !role) {
        return next(new CustomError("At least 1 field is required", 400))
    }

    try {

        const user = await User.findById(id)

        if (!user) return next(new CustomError("User not found!", 404))

        if (email || username) {
            const existing_user = await User.findOne({$or: [{'username': username}, {'email': email}]})

            if (existing_user && existing_user._id !== id) {
                return next(new CustomError("A user with this username or email address already exists.", 400))
            }
        }

        if (email) user.email = email
        if (username) user.username = username
        if (role && (role.toUpperCase() === "USER" || role.toUpperCase() === "ADMIN")) {
            user.role = role.toUpperCase()
        }

        if(uploaded_file) {
            if(user.avatar && user.avatar.public_id) {
                await cloudinary.uploader.destroy(user.avatar.public_id)
            }

            const result = await cloudinary.uploader.upload(`data:${uploaded_file.mimetype};base64,${uploaded_file.buffer.toString('base64')}`, {
                folder: 'auth-app'
            })

            user.avatar.url = result.url
            user.avatar.public_id = result.public_id
        }

        await user.save()

        res.status(200).json({success: true, message: "User updated successfully"})

    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during updating user!.", 500));
    }
}

export const ban_user = async (req, res, next) => {

    const {user_id: banned_user_id, reason: ban_reason, expire} = req.body
    let ban_expire_date;

    const UNIT_TO_MS = {
        "M": 1000 * 60,
        "H": 1000 * 60 * 60,
        "D": 1000 * 60 * 60 * 24,
        "W": 1000 * 60 * 60 * 24 * 7,
        "MO": 1000 * 60 * 60 * 24 * 30,
        "Y": 1000 * 60 * 60 * 24 * 365,
    }

    try {

        if (!banned_user_id || !ban_reason || !expire) {
            return next(new CustomError("The ID of the user you want to ban, the reason for the ban, and the ban expiration date are required.", 409))
        }

        const user = await User.findById(banned_user_id)

        if (!user) return next(new CustomError("User not found", 404))
        if (user.isBanned) return next(new CustomError("User already banned", 409))

        if (expire !== "P") {
            const regex = /(\d+)(M|H|D|W|MO)/
            const match = expire.match(regex)

            if (match) {
                const value = parseInt(match[1], 10)
                const unit = match[2]
                const ms = UNIT_TO_MS[unit]

                if (ms) {
                    ban_expire_date = new Date(Date.now() + (ms * value))
                }
            }
        } else if (expire === "P") {
            ban_expire_date = null
        }


        user.ban_status.is_banned = true
        user.ban_status.ban_expire = ban_expire_date
        user.ban_status.ban_reason = ban_reason
        await user.save()

        if (ban_expire_date) {
            scheduleUnbanJob(user._id, ban_expire_date)
        }

        return res.status(200).json({success: true, message: "User Banned"})

    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during user banned.", 500));
    }
}

export const unban_ban_user = async (req, res, next) => {

    const {user_id: banned_user_id} = req.body

    try {

        const user = await User.findById(banned_user_id)

        if (!user) return next(new CustomError("User not found", 404))
        if (!user.ban_status.is_banned) return next(new CustomError("The user is not already banned", 409))

        user.ban_status.is_banned = false
        user.ban_status.ban_reason = undefined
        user.ban_status.ban_expire = undefined

        await user.save()

        return res.status(200).json({success: true, message: "User ban removed"})

    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during user remove ban.", 500));
    }
}

export const admin_user_delete = async (req, res, next) => {

    const id = req.params.id

    if (!id) return next(new CustomError("ID is required!", 400))

    try {

        const user = await User.findByIdAndDelete(id)

        if (!user) return next(new CustomError("User not found!", 404))

        if(user.avatar && user.avatar.public_id) {
            await cloudinary.uploader.destroy(user.avatar.public_id)
        }

        res.status(200).json({success: true, message: "User deleted successfully"})

    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during deleting user!.", 500));
    }
}