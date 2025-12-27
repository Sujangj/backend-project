import { asyncHandler } from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { ApiResponse } from '../utils/ApiResponse.js';

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    const { fullname, username, email, password } = req.body;
    console.log("email:", email );
    
    //validation - not empty
    if ([fullname, username, email, password].some(field => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required");

    }

    // check if user already exists: email, username
    const existedUser = username.findOne({
        $or: [{ email }, { username }],
    })
    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists");
    }

    //check for Images, check for avatar
    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required");
    }

    // upload the files to cloudinary, avatar and coverImage
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required");
    }

    // create user object - create entry in db
    const user = await User.create({
        fullname,
        username: username.toLowerCase(),
        email,
        password,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
    });

    // remove password and refreshToken field from response
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if (!createdUser) {
        throw new ApiError(500, "something went wrong, while registering user");
    }

    //return success response
    return res.status(201).json(
        new ApiResponse(201, createdUser, "User registered successfully")
    );


    res.status(200).json({
        message: "Ok",
        data: { fullname, username, email }
    });
});

export { registerUser };
