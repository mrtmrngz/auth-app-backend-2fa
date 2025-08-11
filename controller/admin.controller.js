import CustomError from "../helpers/customError.js";
import User from "../models/User.model.js";


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


        const [last_registered_users, weekly_registration, banned_users] = await Promise.all([
            User.find().sort({ createdAt: 1 }).limit(10).select("email avatar username role"),
            User.aggregate([
                {
                    $match: {
                        createdAt: {$gte: oneWeekAgo},
                        isVerified: {$eq: true}
                    }
                },
                {
                    $addFields: {
                        trCreatedAt: { $add: ["$createdAt", 3 * 60 * 60 * 1000] }
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
            User.find({isBanned: true}).select("email username avatar")
        ])

        res.status(200).json({weekly_registration: weekly_registration, last_ten: last_registered_users, banned_users})
    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during registration.", 500));
    }
}

export const ban_user = async (req, res, next) => {

    const { user_id: banned_user_id } = req.body

    try {

        const user = await User.findById(banned_user_id)

        if(!user) return next(new CustomError("User not found", 404))
        if(user.isBanned) return next(new CustomError("User already banned", 409))

        user.isBanned = true
        await user.save()

        return res.status(200).json({success: true, message: "User Banned"})

    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during registration.", 500));
    }
}

export const unban_ban_user = async (req, res, next) => {

    const { user_id: banned_user_id } = req.body

    try {

        const user = await User.findById(banned_user_id)

        if(!user) return next(new CustomError("User not found", 404))
        if(!user.isBanned) return next(new CustomError("The user is not already banned", 409))

        user.isBanned = false
        await user.save()

        return res.status(200).json({success: true, message: "User ban removed"})

    } catch (error) {
        console.error("Register Error:", error);
        return next(new CustomError("An error occurred during registration.", 500));
    }
}
