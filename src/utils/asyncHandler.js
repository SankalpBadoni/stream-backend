import { response } from "express"

//Higher order functions i.e. it can take function as parameter. 
// const asyncHandler = (fn) => async (req, res, next) => {
//     try {
//         await fn(req, res, next)
        
//     } catch (error) {
//         res.status(err.code || 500).json({
//             success: false,
//             message: err.message
//         })
//     }
// }

const asyncHandler = (reqHandler) => {
    return (req, res, next) => {
        Promise.resolve(reqHandler(req, res, next)).catch((err) => next(err))
    }
}

export  {asyncHandler}