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

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken
}