package nativejni;

import android.os.Handler;
import android.os.Message;

import com.example.xquicandroiddemo.C;

public class SendNative {


    static {
        System.loadLibrary("native-lib");
    }

    private Handler mainActivityHandler;

    public void setHandler(Handler h) {
        mainActivityHandler = h;
    }

    public void callback(byte[] bodyContent) {
        Message printmsg = mainActivityHandler.obtainMessage(C.msgTypePrintBodyContent, new String(bodyContent));
        mainActivityHandler.sendMessage(printmsg);
    }

    public native int Send(SendConfig sc);
}
