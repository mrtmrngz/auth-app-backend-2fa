import cron from 'node-cron'
import schedule from "node-schedule";
import User from "../models/User.model.js";

export const scheduleUnbanJob = (user_id, ban_expire_date) => {
    if(!ban_expire_date) {
        return;
    }

    schedule.scheduleJob(ban_expire_date, async () => {
        try{
            const user = await User.findById(user_id)

            if(user && user.ban_status.is_banned) {
                user.ban_status.is_banned = false
                user.ban_status.ban_expire = undefined
                user.ban_status.ban_reason = undefined
                await user.save()
            }

        }catch (err) {
            console.log(`[NODE-SCHEDULE]: Something goes wrong during schedule job! ${user_id}`)
        }
    })
}

export const safe_unban_user = () => {
    cron.schedule('0 */2 * * *', async () => {
        const now = new Date()
        await User.updateMany(
            {
                "ban_status.is_banned": true,
                "ban_status.ban_expire": { $lte: now, $ne: null }
            },
            {
                $set: {
                    "ban_status.is_banned": false,
                    "ban_status.ban_expire": undefined,
                    "ban_status.ban_reason": undefined
                }
            }
        )
    })
}