import jcifs.smb.ACE;
import jcifs.smb.SmbFile;

public class MigrateFile
{
    public static void main(String[] args)
    {
        String sourceUrl = args[0];
        String sourceFileName = args[1];
        String destinationUrl = args[2];
        String destinationFileName = args[3];

        try {

            SmbFile sourceRoot = new SmbFile(sourceUrl);
            SmbFile sourceFile = new SmbFile(sourceRoot, sourceFileName);

            System.out.println("[" + sourceFile.getCanonicalPath() + "] - start migration");

            if (!sourceFile.exists()) {
                System.out.println("[" + sourceFile.getCanonicalPath() + "] - file doesn't exist");
                System.exit(-1);
            }

            SmbFile destinationRoot = new SmbFile(destinationUrl);
            SmbFile destinationFile = new SmbFile(destinationRoot, destinationFileName);

            if (destinationFile.exists()) {
                System.out.println("[" + sourceFile.getCanonicalPath() + "] - destination file [" + destinationFile.getCanonicalPath() + "] exists, removing it first");
                destinationFile.delete();
            }

            System.out.println("[" + sourceFile.getCanonicalPath() + "] - copying file to [" + destinationFile.getCanonicalPath() + "]");
            sourceFile.copyTo(destinationFile);
            System.out.println("[" + sourceFile.getCanonicalPath() + "] - copying file to [" + destinationFile.getCanonicalPath() + "] finished");

            ACE[] security = sourceFile.getSecurity();
            printAces(sourceFile, security);

            System.out.println("[" + sourceFile.getCanonicalPath() + "] - copying security settings to [" + destinationFile.getCanonicalPath() + "]");
            destinationFile.setSecurity(security);

            printAces(destinationFile, destinationFile.getSecurity());

            System.out.println("[" + sourceFile.getCanonicalPath() + "] - migration finished");


        } catch (Exception e) {
            System.out.println("Caught exception while trying to migrate file :" + e);
            e.printStackTrace();
        }

    }

    private static void printAces(SmbFile file, ACE[] aces) {

        System.out.println("[" + file.getCanonicalPath() + "] - ACES -----------------------");
        for (int i = 0; i < aces.length; i++) {
            ACE ace = aces[i];

            System.out.println("\t[" + i + "] - " + ace.toString());
        }
        System.out.println("---------------------------------------------------");
    }
}
