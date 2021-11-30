<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), $this->ruleRegister);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = new User;

        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = password_hash($request->password, PASSWORD_BCRYPT);

        $user->save();

        return response()->json(["status" => "success"], 200);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), $this->ruleLogin);
        if ($validator->fails()) {
            return response()->json(["error" => "Email or password is incorrect"], 400);
        }

        $credentials = $request->only(["email", "password"]);
        if (!$token = Auth::attempt($credentials)) {
            return response()->json(["error" => "Email or password is incorrect"], 401);
        }
        return response()->json(["status" => "success", "token" => $token], 200);
    }

    public function getAuthUser()
    {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(["status" => "user not found"], 404);
            }
        } catch (TokenExpiredException $e) {
            return response()->json(["status" => "token expired"], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(["status" => "token invalid"], 401);
        } catch (JWTException $e) {
            return response()->json(["status" => "token absent"], 401);
        }

        return response()->json(compact('user'));
    }

    public function logout()
    {
        if (Auth::check()) {
            try {
                Auth::logout();
                return response()->json(["status" => "Logout success"], 200);
            } catch (JWTException $e) {
                return response()->json(["error" => $e->getMessage()], 500);
            }
        } else {
            return response()->json(["error" => "Unauthorized"], 401);
        }
    }
}
