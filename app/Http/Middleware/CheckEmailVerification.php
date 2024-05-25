<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class CheckEmailVerification
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        if (Auth::check() && !Auth::user()->hasVerifiedEmail()) {
            // Tambahkan pesan peringatan ke dalam response
            $response->setContent(array_merge($response->original, [
                'warning' => 'Email not verified. Please verify your email to fully access all features.'
            ]));
        }

        return $response;
    }
}
