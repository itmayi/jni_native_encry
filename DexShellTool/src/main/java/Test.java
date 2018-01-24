/**
 * @Author yyt
 * @Date 2018/1/10
 */

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.zip.Adler32;


/**
 * 功能：
 * 1.源apk加密
 * 2.源apk写入壳dex
 */
public class Test {

    static {
        System.load("/Users/yt/IdeaProjects/DexShellTool/lib/libaes.so");
    }

    private static final int MODE = 1;//加密

    public native static void encrypt(String src,String dist,int mode);

    public static void main(String args[]){

        String dirPath = getProjectPath() + "/force/";
        File dir = new File(dirPath);
        //新建文件夹
        createDir(dir);
        //解压源apk和壳apk
        String srcApkPath = dirPath + "srcApk.apk";
        String shellApkPath = dirPath + "unshell.apk";
        decodeApk(shellApkPath);
        //修改AndroidManifest.xml文件
        modifyManifest(srcApkPath,shellApkPath);
        //加壳
        reinForce(srcApkPath,shellApkPath);
        //重打包签名
        rebuildAndSign(shellApkPath);
        //清理文件夹
//        cleanDir(dir);


    }

    /**
     * 签名重打包应用
     * @param srcApkPath
     */
    private static void rebuildAndSign(String srcApkPath){
        String apkName= getApkName(srcApkPath);
        String forcePath = getProjectPath() + "/force/";
        String resultPath = getProjectPath() + "/result/";
        String apkPath = forcePath + apkName; //  ../force/unshell/
        String rebuildPath = resultPath + apkName +"_rebuild.apk";
        String cmdRebuild = MessageFormat.format("/usr/local/bin/apktool b {0} -o {1}",apkPath,rebuildPath);
        callShell(cmdRebuild);
        String keyStorePath = resultPath + "test.keystore";
        String signedOutPath = resultPath + apkName + "_resign.apk";
        String keyStoreAlias = "key0";
        String key = "123456";
        String cmdSign = MessageFormat.format("/Library/Java/JavaVirtualMachines/jdk1.8.0_144.jdk/Contents/Home/bin/jarsigner -verbose -keystore {0} -storepass {1} -keypass {2} -signedjar {3} {4} {5}",keyStorePath,key,key,signedOutPath,rebuildPath,keyStoreAlias);
        callShell(cmdSign);
    }


    /**
     * 修改AndroidManifest.xml
     * @param srcApkPath
     * @param shellDexPath
     */
    private static void modifyManifest(String srcApkPath,String shellDexPath) {
        String srcXmlPath = getProjectPath() + "/force/" + getApkName(srcApkPath) + "/AndroidManifest.xml";
        String shellXmlPath = getProjectPath() + "/force/" + getApkName(shellDexPath) + "/AndroidManifest.xml";
        try {
            FileInputStream srcXML = new FileInputStream(srcXmlPath);
            FileInputStream shellXML = new FileInputStream(shellXmlPath);

            SAXReader reader = new SAXReader();
            Document documentSrc = reader.read(srcXML);
            Document documentShell = reader.read(shellXML);

            srcXML.close();
            shellXML.close();

            Element rootElement = documentSrc.getRootElement();
            Element rootElement_ = documentShell.getRootElement();
            System.out.print("rootElment:" + rootElement.getName() + "\n");

            Element element = rootElement.element("application");
            Element elment_ = rootElement_.element("application");
            System.out.print("elment:" + element.getName() + "\n");

            //获取application name
            Attribute attributeSrc = element.attribute("name");
            Attribute attributeShell = elment_.attribute("name");
            String applicationName_src = "";
            if (attributeSrc != null){
                applicationName_src = attributeSrc.getStringValue();
                System.out.print("applicationName:" + applicationName_src + "\n");
            }else {
                System.out.print("未找到android:name的值\n");
                return;

            }
            String applicationName_shell = "";
            if (attributeShell != null){
                applicationName_shell = attributeShell.getStringValue();
                System.out.print("applicationNameShell:" + applicationName_shell + "\n");
            }

            //修改application节点android:name属性值为壳apk application name
            attributeSrc.setValue(applicationName_shell);
            //在源apkAndroidManifest文件添加节点
            Element metaElement = rootElement.element("meta-data");
            if (metaElement == null){
                metaElement = element.addElement("meta-data");
                metaElement.addAttribute("android:name", "APPLICATION_CLASS_NAME");
                metaElement.addAttribute("android:value", applicationName_src);
            }

            FileOutputStream out = new FileOutputStream(srcXmlPath);
            OutputFormat format = OutputFormat.createPrettyPrint();
            format.setEncoding("UTF-8");
            XMLWriter writer = new XMLWriter(out, format);
            writer.write(documentSrc);
            writer.close();
            out.close();
        } catch (DocumentException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e){
            e.printStackTrace();
        }finally {

        }
    }

    /**
     * 获取apk name
     * @param apkPath
     * @return
     */
    private static String getApkName(String apkPath){
        int index_ = apkPath.lastIndexOf("/");
        String apkName = apkPath.substring(index_ + 1);
        apkName = apkName.replace(".apk","");
        return apkName;
    }
    /**
     * 解压apk
     */
    public static void decodeApk(String apkPath){
        String outPutDir = getProjectPath() + "/force/" + getApkName(apkPath);

        String cmd = MessageFormat.format("/usr/local/bin/apktool d -s {0} -o {1}",apkPath,outPutDir);
        callShell(cmd);
    }


    /**
     * 执行shell命令
     * @param cmd
     * @return
     */
    private static void callShell(String cmd){
        BufferedReader brError = null;
        BufferedReader input = null;
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(cmd);
            //读取标准输出流
            input = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = "";
            while ((line = input.readLine())!= null){
                System.out.print(line + "\n");
            }
            //读取标准错误流
            brError = new BufferedReader(new InputStreamReader(process.getErrorStream(),"gb2312"));
            String errLine = "";
            while ((errLine = brError.readLine()) != null){
                System.out.print(errLine + "\n");
            }
            //终止进程
            try {
                int exitValue = process.waitFor();
                System.out.print(cmd + " exitValue:" + exitValue + "\n");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            process.destroy();
        }catch (  IOException e){
            System.out.print("process exception: " + e.getMessage());
        }finally {
            try {
                if (input != null){
                    input.close();
                }
                if (brError != null){
                    brError.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (process != null){
                process.destroy();
            }
        }
    }

    /**
     * 加壳
     */
    public static void reinForce(String srcApk,String shellApk){
        String apkOut = getProjectPath() + "/lib/yu_rf.txt";
        String unshellDex = getProjectPath() + "/force/" + getApkName(shellApk) + "/classes.dex";

        File unshellDexFile = new File(unshellDex);

        encrypt(srcApk,apkOut,MODE);

        File srcAes = new File(apkOut);//加密后file

        byte[] srcDistArray = readFileBytes(srcAes);
        byte[] unshellDexArray = readFileBytes(unshellDexFile);

        int srcApkLength = srcDistArray.length;
        int unshellDexLength = unshellDexArray.length;
        int totalLenfth = srcApkLength + unshellDexLength + 4;

        byte[] newDexArray = new byte[totalLenfth];

        System.arraycopy(unshellDexArray,0,newDexArray,0,unshellDexLength); //先拷贝壳dex
        System.arraycopy(srcApkLength,0,newDexArray,unshellDexLength,srcApkLength);  //拷贝源apk
        System.arraycopy(intToByte(srcApkLength),0,newDexArray,totalLenfth - 4,4);  //源apk大小

        fixFileSizeHeader(newDexArray);
        fixSHA1Header(newDexArray);
        fixCheckSumHeader(newDexArray);

        //替换壳classes.dex
        try {
            if(unshellDexFile.exists()){
                unshellDexFile.delete();
            }
            FileOutputStream localFileOutputStream = new FileOutputStream(unshellDex);  //将混合后的dex文件写回原壳位置
            localFileOutputStream.write(newDexArray);
            localFileOutputStream.flush();
            localFileOutputStream.close();

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    /**
     * 修改dex头，CheckSum 校验码
     * @param dexBytes
     */
    private static void fixCheckSumHeader(byte[] dexBytes) {
        Adler32 adler = new Adler32();
        adler.update(dexBytes, 12, dexBytes.length - 12);//从12到文件末尾计算校验码
        long value = adler.getValue();
        int va = (int) value;
        byte[] newcs = intToByte(va);
        //高位在前，低位在前掉个个
        byte[] recs = new byte[4];
        for (int i = 0; i < 4; i++) {
            recs[i] = newcs[newcs.length - 1 - i];
            System.out.println(Integer.toHexString(newcs[i]));
        }
        System.arraycopy(recs, 0, dexBytes, 8, 4);//效验码赋值（8-11）
        System.out.println(Long.toHexString(value));
        System.out.println();
    }

    /**
     * 修改dex头 sha1值
     * @param dexBytes
     * @throws NoSuchAlgorithmException
     */
    private static void fixSHA1Header(byte[] dexBytes) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        md.update(dexBytes, 32, dexBytes.length - 32);//从32为到结束计算sha--1
        byte[] newdt = md.digest();
        System.arraycopy(newdt, 0, dexBytes, 12, 20);//修改sha-1值（12-31）
        //输出sha-1值，可有可无
        String hexstr = "";
        for (int i = 0; i < newdt.length; i++) {
            hexstr += Integer.toString((newdt[i] & 0xff) + 0x100, 16)
                    .substring(1);
        }
        System.out.println(hexstr);
    }

    /**
     * 修改dex头 file_size值
     * @param dexBytes
     */
    private static void fixFileSizeHeader(byte[] dexBytes) {
        //新文件长度
        byte[] newfs = intToByte(dexBytes.length);
        System.out.println(Integer.toHexString(dexBytes.length));
        byte[] refs = new byte[4];
        //高位在前，低位在前掉个个
        for (int i = 0; i < 4; i++) {
            refs[i] = newfs[newfs.length - 1 - i];
            System.out.println(Integer.toHexString(newfs[i]));
        }
        System.arraycopy(refs, 0, dexBytes, 32, 4);//修改（32-35）
    }


    /**
     * 整形转字节数组
     * @param number
     * @return
     */
    public static byte[] intToByte(int number) {
        byte[] b = new byte[4];
        for (int i = 3; i >= 0; i--) {
            b[i] = (byte) (number % 256);
            number >>= 8;
        }
        return b;
    }

    /**
     * 加密源apk（对每个字节异或）
     * @param srcData
     * @return
     */
//    private static byte[] encrpt(byte[] srcData){
//        for(int i = 0;i<srcData.length;i++){
//            srcData[i] = (byte)(0xFF ^ srcData[i]);
//        }
//        return srcData;
//    }
    /**
     * 以二进制形式读取文件内容
     * @param file
     * @return
     * @throws IOException
     */

    private static byte[] readFileBytes(File file) {
        byte[] arrayOfByte = new byte[1024];
        ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fis = null;
        if (file.canRead()){
            try {
                fis = new FileInputStream(file);
                int len;
                while ((len = fis.read(arrayOfByte)) != -1){
                    localByteArrayOutputStream.write(arrayOfByte,0,len);
                }
                fis.close();
                return localByteArrayOutputStream.toByteArray();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * 创建环境目录
     * @param dir
     */
    public static void createDir(File dir){
        if (!dir.exists()){
            dir.mkdir();
        }
    }

    /**
     * 获取工程路径
     * @return
     */

    public static String getProjectPath(){
        return System.getProperty("user.dir");

    }
    /**
     * 清空目录
     * @return
     */
    public static void cleanDir(File dir){
        if (dir.isDirectory()){
            String[] children = dir.list();
            for (int i = 0; i < children.length; i++) {
                cleanDir(new File(dir,children[i]));
            }
        }
        dir.delete();
    }

}
