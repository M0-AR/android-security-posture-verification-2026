package com.example.synthetic;

import android.content.SharedPreferences;
import android.util.Log;

public class SyntheticStorage {
    public void demo(android.content.Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences("creds", 0);
        p.edit().putString("token", "DO-NOT-DO-THIS-IN-REAL-CODE").apply();
        Log.d("TAG", "token=" + "DO-NOT-DO-THIS");
        String url = "http://example.com/health";
    }
}
