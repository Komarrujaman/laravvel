<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {

        $data = [
            'name' => 'required',
            'email' => ['required', 'email', 'unique:users'],
            'password' => ['required', 'min:8']
        ];

        $validator = Validator::make($request->all(), $data);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()
            ], 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' =>  Hash::make($request->password)
        ])->sendEmailVerificationNotification();

        return response()->json([
            'status' => true,
            'message' => 'register successful',
            'data' => [
                'name' => $request->name,
                'email' => $request->email,
            ]
        ], 200);
    }


    public function login(Request $request)
    {
        $data = [
            'email' => 'required|email',
            'password' => 'required'
        ];

        $validator = Validator::make($request->all(), $data);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()
            ], 400);
        }

        if (!Auth::attempt($request->only(['email', 'password']))) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid Credentials'
            ], 401);
        }

        $user = User::where('email', $request->email)->first();
        if ($user::where('email_verified_at') === null) {
            return response()->json([
                'status' => true,
                'message' => 'login successful',
                'user' => $user->email,
                'Authorization' => [
                    'token' => $user->createToken('user-token', ['*'], now()->addHour())->plainTextToken,
                    'token_type' => 'Bearer',
                    'expires_at' => now()->addHour()->toDateTimeString()
                ],
                'notification' => 'Please verification your email'
            ]);
        }

        return response()->json([
            'status' => true,
            'message' => 'login successful',
            'user' => $user->email,
            'Authorization' => [
                'token' => $user->createToken('user-token', ['*'], now()->addHour())->plainTextToken,
                'token_type' => 'Bearer',
                'expires_at' => now()->addHour()->toDateTimeString()
            ]
        ]);
    }

    public function logout(Request $request)
    {
        $user = new User();
        $user->tokens()->delete();
        $request->user()->currentAccessToken()->delete();
        return response()->json([
            'status' => true,
            'message' => 'logout successful'
        ]);
    }


    public function verify($id, Request $request)
    {
        if (!$request->hasValidSignature()) {
            return response()->json([
                'status' => false,
                'message' => 'Verification email failed'
            ], 401);
        }

        $user = User::find($id);

        if (!$user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
            return response()->json([
                'status' => true,
                'message' => 'verification successful'
            ], 200);
        }
    }
}
