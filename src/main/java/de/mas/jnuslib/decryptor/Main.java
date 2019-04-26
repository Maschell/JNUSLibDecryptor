/****************************************************************************
 * Copyright (C) 2019 Maschell
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/

package de.mas.jnuslib.decryptor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.UnrecognizedOptionException;

import de.mas.wiiu.jnus.DecryptionService;
import de.mas.wiiu.jnus.NUSTitle;
import de.mas.wiiu.jnus.NUSTitleLoaderLocal;
import de.mas.wiiu.jnus.Settings;
import de.mas.wiiu.jnus.entities.TMD;
import de.mas.wiiu.jnus.entities.Ticket;
import de.mas.wiiu.jnus.implementations.FSTDataProviderNUSTitle;
import de.mas.wiiu.jnus.utils.Utils;

public class Main {
    private final static String OPTION_IN = "in";
    private final static String OPTION_HELP = "help";
    private static final String OPTION_OUT = "out";
    private static final String OPTION_COMMON_KEY = "commonkey";
    private static final String OPTION_TITLEKEY = "titlekey";
    private static final String OPTION_OVERWRITE = "overwrite";
    private static final String OPTION_FILE = "file";
    private static byte[] commonKey;

    private static final String HOMEPATH = System.getProperty("user.home") + File.separator + ".wiiu";

    public static void main(String[] args) throws Exception {
        System.out.println("JNUSLib Decryptor 0.1 - Maschell");
        System.out.println();
        Options options = getOptions();

        if (args.length == 0) {
            showHelp(options);
            return;
        }

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (MissingArgumentException e) {
            System.out.println(e.getMessage());
            return;
        } catch (UnrecognizedOptionException e) {
            System.out.println(e.getMessage());
            showHelp(options);
            return;
        }

        String input = null;
        String output = null;
        boolean overwrite = false;
        byte[] titlekey = null;

        readKey(new File(HOMEPATH + File.separator + "common.key")).ifPresent(key -> Main.commonKey = key);
        readKey(new File("common.key")).ifPresent(key -> Main.commonKey = key);

        if (cmd.hasOption(OPTION_HELP)) {
            showHelp(options);
            return;
        }

        if (cmd.hasOption(OPTION_IN)) {
            input = cmd.getOptionValue(OPTION_IN);
        }
        if (cmd.hasOption(OPTION_OUT)) {
            output = cmd.getOptionValue(OPTION_OUT);
        }

        if (cmd.hasOption(OPTION_COMMON_KEY)) {
            String commonKey = cmd.getOptionValue(OPTION_COMMON_KEY);
            byte[] key = Utils.StringToByteArray(commonKey);
            if (key.length == 0x10) {
                Main.commonKey = key;
                System.out.println("Commonkey was set to: " + Utils.ByteArrayToString(key));
            }
        }

        if (cmd.hasOption(OPTION_TITLEKEY)) {
            String titlekey_string = cmd.getOptionValue(OPTION_TITLEKEY);
            try {
                titlekey = Utils.StringToByteArray(titlekey_string);
            } catch (StringIndexOutOfBoundsException e) {
                System.err.println("Titlekey has the wrong size");
            }
            if (titlekey.length != 0x10) {
                titlekey = null;
                System.err.println("Titlekey has the wrong size, expecting 16 bytes as Hex String");
            } else {
                System.out.println("Titlekey was set to: " + Utils.ByteArrayToString(titlekey));
            }
        }

        if (cmd.hasOption(OPTION_OVERWRITE)) {
            overwrite = true;
        }

        String regex = ".*";

        if (cmd.hasOption(OPTION_FILE)) {
            regex = cmd.getOptionValue(OPTION_FILE);
            System.out.println("Decrypting files matching \"" + regex + "\"");
        }
        decryptFile(input, output, regex, overwrite, titlekey);
    }

    private static NUSTitle getTitle(String input, boolean overwrite, byte[] titlekey) throws IOException, Exception {
        if (input == null) {
            System.out.println("You need to provide an input file");
        }
        File inputFile = new File(input);

        System.out.println("Handling: " + inputFile.getAbsolutePath());

        NUSTitle title = null;

        if (titlekey != null) {
            title = NUSTitleLoaderLocal.loadNUSTitle(inputFile.getAbsolutePath(), Ticket.createTicket(titlekey,
                    TMD.parseTMD(new File(inputFile.getAbsolutePath() + File.separator + Settings.TMD_FILENAME)).getTitleID(), Main.commonKey));
        } else {
            title = NUSTitleLoaderLocal.loadNUSTitle(inputFile.getAbsolutePath(), Main.commonKey);
        }

        return title;
    }

    private static void decryptFile(String input, String output, String regex, boolean overwrite, byte[] titlekey) throws Exception {
        NUSTitle title = getTitle(input, overwrite, titlekey);

        if (title == null) {
            System.err.println("Failed to open title.");
            return;
        }

        String newOutput = output;

        if (newOutput == null) {
            newOutput = String.format("%016X", title.getTMD().getTitleID());
        } else {
            newOutput += File.separator + String.format("%016X", title.getTMD().getTitleID());
        }

        File outputFolder = new File(newOutput);

        System.out.println("To the folder: " + outputFolder.getAbsolutePath());
        DecryptionService decryption = DecryptionService.getInstance(new FSTDataProviderNUSTitle(title));

        decryption.decryptFSTEntriesTo(regex, outputFolder.getAbsolutePath(), overwrite);

        System.out.println("Decryption done");
    }

    private static Optional<byte[]> readKey(File file) {
        if (file.isFile()) {
            byte[] key;
            try {
                key = Files.readAllBytes(file.toPath());
                if (key != null && key.length == 16) {
                    return Optional.of(key);
                }
            } catch (IOException e) {
            }
        }
        return Optional.empty();
    }

    private static Options getOptions() {
        Options options = new Options();
        options.addOption(
                Option.builder(OPTION_IN).argName("input file").hasArg().desc("Input file. Expects a folder which contains the .app, and .tmd files.").build());
        options.addOption(Option.builder(OPTION_OUT).argName("output path").hasArg().desc("The path where the result will be saved").build());

        options.addOption(Option.builder(OPTION_OVERWRITE).desc("Optional. Overwrites existing files").build());
        options.addOption(Option.builder(OPTION_COMMON_KEY).argName("WiiU common key").hasArg()
                .desc("Optional. HexString. Will be used if no \"common.key\" in the folder of this .jar is found").build());
        options.addOption(Option.builder(OPTION_TITLEKEY).argName("Ticket title key").hasArg()
                .desc("Optional. HexString. Will be used if no \"title.tik\" in the folder is found").build());
        options.addOption(Option.builder(OPTION_FILE).argName("regular expression").hasArg()
                .desc("Decrypts the files that matches the given regular expression.").build());

        options.addOption(OPTION_HELP, false, "shows this text");

        return options;
    }

    private static void showHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(100);
        formatter.printHelp(" ", options);
    }

}
