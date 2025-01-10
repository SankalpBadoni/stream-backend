import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js";
import {User} from "../models/user.model.js";
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"

const generateAccessAndRefreshToken = async(userId) => 
{
    try {
        const user = await User.findById(userId)
        const accesstoken = user.generateAccessToken()
        const refreshtoken = user.generateRefreshToken()

        user.refreshToken = refreshtoken //refreshToken is in user.model.js
        await user.save( {validateBeforeSave : false } )

        return {accesstoken, refreshtoken}

    } catch (error) {
        throw new ApiError(500, 'Something went wrong while generating access and refresh token')
    }
}

const registerUser = asyncHandler( async(req, res) => {
    const {fullname, email, username, password} = req.body
    //console.log("email :", email);
    
    if(fullname===""){
        throw new ApiError(400, "full name is reuired")
    }
    if(email===""){
        throw new ApiError(400, "email is reuired")
    }
    if(username===""){
        throw new ApiError(400, "username is reuired")
    }
    if(password===""){
        throw new ApiError(400, "password is reuired")
    }

    const existingUser = await User.findOne({
        $or: [ { username }, { email } ]
    })
   // console.log("Existing user:", existingUser);

    if(existingUser){
        throw new ApiError(409, "user already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar is required")
    }

    const user = await User.create({
        fullname,
        avatar : avatar.url,
        coverImage : coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User Registered Successfully")
    )

} )

const loginUser = asyncHandler( async(req,res)=> {
    const{email, username, password} = req.body

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }
    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    if(!user){
        throw new ApiError(404, 'User does not exist')
    }

    const isPasswordValid =  await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401, 'Password Incorrect')
    }

    const accesstoken = user.generateAccessToken();
    const refreshtoken = user.generateRefreshToken();
    console.log('Access Token:', accesstoken);
    console.log('Refresh Token:', refreshtoken);
    const loggedinUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly : true,
        secure : false,
        sameSite: 'Lax'
    }

    return res.status(200)
    .cookie("accessToken", accesstoken, options)
    .cookie("refreshToken", refreshtoken, options)
    .json(
        new ApiResponse(
            200,
            {
                user : loggedinUser, refreshtoken,accesstoken
            },
            "User loggedin successfully"
        )
    )

})

const logoutUser = asyncHandler(async(req,res)=> {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    );
    
    const options = {
        httpOnly : true,
        secure : process.env.NODE_ENV === "production",
    }
    return res.status(200)
    .clearCookie("accesstoken", options)
    .clearCookie("refreshtoken", options)
    .json(new ApiResponse(200, {}, "User logged out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorised Error")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh token is expired")
        }
        const options = {
            httpOnly : true
        }
    
        const{accesstoken, newRefreshtoken} = await generateAccessAndRefreshToken(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accesstoken, options)
        .cookie("refreshToken", newRefreshtoken, options)
        .json(
            new ApiResponse(
                200,
                {accesstoken, refreshtoken : newRefreshtoken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const {oldPassword, newPassword} = req.body
    const user = await User.findById(req.user?._id)
    const isPasswordCorrect =  await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid old password")
    }
    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))
})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
    .status(200)
    .json(200, req.user, "current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async (req, res) => {
    const {fullname, email} = req.body

    if(!fullname || !email){
        throw new ApiError(400, "All fields are required")
    }

    const user = User.findById(
        req.user?._id,
        {
            $set: {
                fullname,
                email : email
            }
        },
        {new : true} //isse update info show hoti hai
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    if(!avatar.url){
        throw new ApiError(400, "Error while uploading on cloudinary")
    }

    await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar : avatar.url
            }
        },
        {new : true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar updated")
    )
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400, "Cover Image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage : coverImage.url
            }
        },
        {new : true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover Image updated")
    )
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const {username} = req.params
    if(!username?.trim()){
        throw new ApiError(400, 'username is missing')
    }

    //User.find({username}) isme pehle DB se user lenge fir uski id ke basis pe aggregate karenge par itna karne ki zarurat nhi, we can directly use -
    const channel = await User.aggregate([
        {
            $match: {
                username : username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from : "subscriptions", //it has to be "Subscription" but in model everything becomes lowercase and plural
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from : "subscriptions", //it has to be "Subscription" but in model everything becomes lowercase and plural
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount : {
                    $size: "$subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers?.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullname: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(400, "channel does not exist")
    }

    res
    .status(200)
    .json( new ApiResponse(200, channel[0], "user channel fetched successfully"))

})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    updateUserCoverImage,
    getUserChannelProfile
}