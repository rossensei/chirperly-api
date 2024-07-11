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
use Exception;

class AuthController extends Controller
{
    use HttpResponses;

    public function register(RegisterUserRequest $request)
    {
        $user = User::create([
            'name' => $request->name,
            'username' => $request->username,
            'password' => Hash::make($request->password)
        ]);

        return $this->success(['user' => $user], 'Account has been created successfully.', 201);
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
    }

    public function me()
    {
        try {
            return Auth::user();
        } catch(Exception $e) {
            return $this->error(null, $e, 400);
        }
    }

    public function logout(Request $request)
    {
        // Auth::user()->currentAccessToken()->delete();
        $request->user()->currentAccessToken()->delete();

        return $this->success([
            'message' => 'You have successfully been logged out!',
        ]);
    }
}
