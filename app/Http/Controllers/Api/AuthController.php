<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Traits\HttpResponses;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterUserRequest;

class AuthController extends Controller
{
    use HttpResponses;

    public function register(RegisterUserRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'username' => $request->username,
            'password' => bcrypt($request->password)
        ]);

        return $this->success([
            'user' => $user,
            'token' => $user->createToken($user->name.'-AuthToken')->plainTextToken,
        ]);

        // return response()->json([
        //     'status' => 'success',
        //     'message' => "You have successfully registered your account!"
        // ], 201);
    }

    public function login(LoginRequest $request)
    {
        if(!Auth::attempt($request->only(['username', 'password']))) {
            return $this->error(null, 'Credentials do not match our records', 401);
        }

        $user = User::where('username', $request->username)->first();

        return $this->success([
            'user' => $user,
            'token' => $user->createToken($user->name.'-AuthToken')->plainTextToken
        ]);
        // $token = $user->createToken($user->name.'-AuthToken')->plainTextToken;

        // return response()->json([
        //     'status' => 'success',
        //     'message' => 'Login successful.',
        //     'access_token' => $token
        // ], 200);
    }

    public function me(Request $request)
    {
        return Auth::user();
    }
}
