package com.example.xquicandroiddemo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import nativejni.SendConfig;
import nativejni.SendNative;

public class MainActivity extends AppCompatActivity {

    private String serverAddr;
    private int serverPort;

    private int reqParal;
    private int reqMax;
    private int bodySize2Send;
    private int verifyCertAllowSelfSign;
    private String url;

    private int pacingOn;
    private int transportLayer;
    private int force1RTT;
    private int echoCheckOn;
    private int ipv6;
    private int noCrypt;

    private String CCType;
    private String requestType;

    private Handler mHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_PAN);
        setContentView(R.layout.activity_main);

        mHandler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                super.handleMessage(msg);
                switch (msg.what) {
                    case C.msgTypePrintBodyContent:
                        String bodyContent = (String)msg.obj;
                        Toast toast = Toast.makeText(getApplicationContext(), bodyContent, Toast.LENGTH_LONG);
                        toast.show();
                        break;
                    default:
                        break;
                }
            }
        };

        findViewById(R.id.btn_send).setOnClickListener(this::ClientTest);

    }

    private void ClientTest(View view) {
        // config UI control
        serverAddr = ((EditText)findViewById(R.id.etServerAddr)).getText().toString();
        serverPort = Integer.parseInt(((EditText)findViewById(R.id.etServerPort)).getText().toString());
        reqParal = Integer.parseInt(((EditText)findViewById(R.id.etReqParal)).getText().toString());
        reqMax = Integer.parseInt(((EditText)findViewById(R.id.etReqMax)).getText().toString());
        bodySize2Send = Integer.parseInt(((EditText)findViewById(R.id.etBodySize2Send)).getText().toString());
        verifyCertAllowSelfSign = Integer.parseInt(((EditText)findViewById(R.id.etVerifyCertAllowSelfSign)).getText().toString());
        url = ((EditText)findViewById(R.id.etUrl)).getText().toString();

        pacingOn = ((CheckBox)findViewById(R.id.cb_pacing_on)).isChecked() ? 1 : 0;
        transportLayer = ((CheckBox)findViewById(R.id.cb_transport_layer)).isChecked() ? 1 : 0;
        force1RTT = ((CheckBox)findViewById(R.id.cb_force_1RTT)).isChecked() ? 1 : 0;
        echoCheckOn = ((CheckBox)findViewById(R.id.cb_echo_check_on)).isChecked() ? 1 : 0;
        ipv6 = ((CheckBox)findViewById(R.id.cb_ipv6)).isChecked() ? 1 : 0;
        noCrypt = ((CheckBox)findViewById(R.id.cb_no_crypt)).isChecked() ? 1 : 0;

        CCType = ((RadioButton)findViewById(((RadioGroup)findViewById(R.id.rg_cc_type)).getCheckedRadioButtonId())).getText().toString();
        requestType = ((RadioButton)findViewById(((RadioGroup)findViewById(R.id.rg_method)).getCheckedRadioButtonId())).getText().toString();

        // register native methods
        SendNative sendNative = new SendNative();
        sendNative.setHandler(mHandler);
        // build sendConfigBuilder,
        SendConfig.Builder sConfigBuilder = new SendConfig.Builder();
        // get config from UI
        sConfigBuilder
                .serverAddress(serverAddr)
                .serverPort(serverPort)
                .requestParallel(reqParal)
                .requestMax(reqMax)
                .bodySizeToSend(bodySize2Send)
                .forceCertVerification(verifyCertAllowSelfSign)
                .Url(url)
                .pacingOn(pacingOn)
                .force1RTT(force1RTT)
                .ipv6(ipv6)
                .noCrypt(noCrypt)
                .CCType(CCType)
                .requestType(requestType);

        Integer ret = sendNative.Send(sConfigBuilder.build());
        Log.d("hhh", ret + "");
    }

}