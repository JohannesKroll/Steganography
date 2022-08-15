import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;


public class Main {

	private static final int  mask      = 0xFFFCFCFC;
	private static final int  mask_2    = 0xFFFCFCFF;
	private static final int  mask_1    = 0xFFFCFFFF;
	private static final int  zeroMask  = 0x00030303;
	private static final byte mask1     = (byte) 0xC0;
	private static final byte mask2     = (byte) 0x30;
	private static final byte mask3     = (byte) 0x0C;
	private static final byte mask4     = (byte) 0x03;
	private static final byte fillMask1 = (byte) 0x3F;
	private static final byte fillMask2 = (byte) 0xCF;
	private static final byte fillMask3 = (byte) 0xF3;
	private static final byte fillMask4 = (byte) 0xFC;


	public static void main( String[] args ) {

		if( args.length == 0 ) {
			System.out.println( "To less parameters!" );
			return;
		}

		Config config = detectFlags( args );
		byte[] keyBytes = "4<+aefgp".getBytes();
		byte[] ivBytes = "83t4oul.".getBytes();
		SecretKeySpec key = new SecretKeySpec( keyBytes, "DES" );
		IvParameterSpec ivSpec = new IvParameterSpec( ivBytes );
		Cipher cipher = null;

		if( config.action != null ) {
			if( config.action ) {
				if( config.image != null ) {
					try {
						BufferedImage img = ImageIO.read( new File( config.image ) );
						byte[] msg = extract( img );
						//cipher = Cipher.getInstance( "DES/CBC/NoPadding" );
						//byte[] decrypt = decrypt( msg, key,ivSpec,cipher);
						String result = new String( msg );
						System.out.println( "Message: " + result );
						BufferedWriter writer = Files.newBufferedWriter( Paths.get( config.file != null ? config.file : "output.txt" ), StandardCharsets.UTF_8 );
						writer.write( result, 0, result.length() );
						writer.close();
					} catch( Exception x ) {
						System.err.format( "Exception: %s%n", x );
					}
				}
			} else {
				if( config.file != null ) {
					try (BufferedReader reader = Files.newBufferedReader( Paths.get( config.file ), StandardCharsets.UTF_8 )) {
						config.message = "";
						String line = null;
						while( ( line = reader.readLine() ) != null ) {
							config.message = config.message.concat( line + "\n" );
						}
					} catch( IOException x ) {
						System.err.format( "IOException: %s%n", x );
					}
				}
				if( config.message != null ) {
					System.out.println( "Message: " + config.message );
					try {
						cipher = Cipher.getInstance( "DES/CBC/NoPadding" );
						/*byte[] msg = config.message.getBytes();
						if (msg.length % 8 != 0) {
							byte[] padding = new byte[msg.length + 8 - (msg.length % 8)];
							System.arraycopy( msg,0,padding,8 - (msg.length % 8),msg.length );
							msg = padding;
						}
						byte[] encryptedMsg = encrypt( msg, key, ivSpec, cipher );*/
						BufferedImage img = ImageIO.read( new File( config.image != null ? config.image : "picture3." + config.type ) );
						img = insert( config.message.getBytes(), img );
						if( img != null ) {
							File outputFile = new File( "output." + config.type );
							ImageIO.write( img, config.type, outputFile );
						}
					} catch( Exception x ) {
						System.err.format( "Exception: %s%n", x );
					}
				}
			}
		}
	}


	private static class Config {

		String  message;
		String  file;
		String  image;
		String  type;
		Boolean action; // false to insert message into image, true to extract message from image


		Config( String message, String file, String image, String type, Boolean action ) {

			this.message = message;
			this.file = file;
			this.image = image;
			this.action = action;
			this.type = type;
		}
	}


	private static Config detectFlags( String[] args ) {

		String message = null;
		String file = null;
		String image = null;
		String type = "png";
		Boolean action = null;
		for( int i = 0; i < args.length; i++ ) {
			switch( args[ i ] ) {
				case "-m":
					String[] strings = concat( Arrays.copyOfRange( args, i + 1, args.length ) );
					message = strings[ 0 ];
					if( strings.length > 1 ) {
						args = strings;
					}
					break;
				case "-f":
					file = args[ ++i ];
					break;
				case "-a":
					if( args[ ++i ].equals( "1" ) || args[ i ].equals( "true" ) ) {
						action = true;
					} else {
						if( args[ i ].equals( "0" ) || args[ i ].equals( "false" ) ) {
							action = false;
						}
					}
					break;
				case "-i":
					image = args[ ++i ];
					break;
				case "-t":
					type = args[ ++i ];
			}
		}
		return new Config( message, file, image, type, action );
	}


	private static String[] concat( String[] msgParts ) {

		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append( msgParts[ 0 ] );
		for( int i = 1; i < msgParts.length; i++ ) {
			if( msgParts[ i ].equals( "-f" ) || msgParts[ i ].equals( "-a" ) || msgParts[ i ].equals( "-i" ) ) {
				String[] strings = new String[ msgParts.length - i + 1 ];
				strings[ 0 ] = stringBuilder.toString();
				System.arraycopy( msgParts, i, strings, 1, strings.length - 1 );
				return strings;
			}
			stringBuilder.append( " " ).append( msgParts[ i ] );
		}
		return new String[]{stringBuilder.toString()};
	}


	private static byte[] encrypt( byte[] bytes, SecretKeySpec key, IvParameterSpec ivSpec, Cipher cipher ) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

		cipher.init( Cipher.ENCRYPT_MODE, key, ivSpec );
		byte[] encrypted = new byte[ cipher.getOutputSize( bytes.length ) ];
		int enc_len = cipher.update( bytes, 0, bytes.length, encrypted, 0 );
		enc_len += cipher.doFinal( encrypted, enc_len );
		return encrypted;
	}


	private static byte[] decrypt( byte[] bytes, SecretKeySpec key, IvParameterSpec ivSpec, Cipher cipher ) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {

		cipher.init( Cipher.DECRYPT_MODE, key, ivSpec );
		byte[] decrypted = new byte[ cipher.getOutputSize( bytes.length ) ];
		int dec_len = cipher.update( bytes, 0, bytes.length, decrypted, 0 );
		dec_len += cipher.doFinal( decrypted, dec_len );
		return decrypted;
	}


	private static BufferedImage insert( byte[] msg, BufferedImage img ) {

		byte[] overflow = new byte[ 4 ];
		int x = 0, y = 0;
		overflow[ 0 ] = 0;
		for( int i = 0; i <= msg.length; i++ ) {
			if( y >= img.getHeight() ) {
				System.out.println( "Too large message, shutting down." );
				return null;
			}
			int rgb = img.getRGB( x, y );
			rgb = rgb & mask;
			if( i < msg.length ) {
				byte[] bytes = new byte[ 4 ];
				bytes[ 0 ] = 0;
				switch( i % 3 ) {
					case 0:
						bytes[ 1 ] = (byte) ( mask1 & msg[ i ] );
						bytes[ 1 ] = (byte) ( bytes[ 1 ] >> 6 );
						bytes[ 2 ] = (byte) ( mask2 & msg[ i ] );
						bytes[ 2 ] = (byte) ( bytes[ 2 ] >> 4 );
						bytes[ 3 ] = (byte) ( mask3 & msg[ i ] );
						bytes[ 3 ] = (byte) ( bytes[ 3 ] >> 2 );
						overflow[ 1 ] = (byte) ( mask4 & msg[ i ] );
						break;
					case 1:
						bytes[ 1 ] = overflow[ 1 ];
						bytes[ 2 ] = (byte) ( mask1 & msg[ i ] );
						bytes[ 2 ] = (byte) ( bytes[ 2 ] >> 6 );
						bytes[ 3 ] = (byte) ( mask2 & msg[ i ] );
						bytes[ 3 ] = (byte) ( bytes[ 3 ] >> 4 );
						overflow[ 1 ] = (byte) ( mask3 & msg[ i ] );
						overflow[ 1 ] = (byte) ( overflow[ 1 ] >> 2 );
						overflow[ 2 ] = (byte) ( mask4 & msg[ i ] );
						break;
					case 2:
						overflow[ 3 ] = (byte) ( mask1 & msg[ i ] );
						overflow[ 3 ] = (byte) ( overflow[ 3 ] >> 6 );
						int result = ByteBuffer.wrap( overflow ).getInt();
						rgb += result;
						img.setRGB( x++, y, rgb );
						overflow = new byte[ 4 ];
						if( x >= img.getWidth() ) {
							x = 0;
							y++;
						}
						rgb = img.getRGB( x, y );
						rgb = rgb & mask;
						bytes[ 1 ] = (byte) ( mask2 & msg[ i ] );
						bytes[ 1 ] = (byte) ( bytes[ 1 ] >> 4 );
						bytes[ 2 ] = (byte) ( mask3 & msg[ i ] );
						bytes[ 2 ] = (byte) ( bytes[ 2 ] >> 2 );
						bytes[ 3 ] = (byte) ( mask4 & msg[ i ] );
						break;
				}

				int result = ByteBuffer.wrap( bytes ).getInt();
				rgb += result;
			} else {
				int result = 0;
				switch( i % 3 ) {
					case 0:
						img.setRGB( x++, y, rgb );
						if( x >= img.getWidth() ) {
							x = 0;
							y++;
						}
						rgb = img.getRGB( x, y );
						rgb = rgb & mask_1;
						break;
					case 1:
						overflow[ 2 ] = 0;
						overflow[ 3 ] = 0;
						result = ByteBuffer.wrap( overflow ).getInt();
						rgb += result;
						img.setRGB( x++, y, rgb );
						if( x >= img.getWidth() ) {
							x = 0;
							y++;
						}
						rgb = img.getRGB( x, y );
						rgb = rgb & mask_2;
						break;
					case 2:
						overflow[ 3 ] = 0;
						result = ByteBuffer.wrap( overflow ).getInt();
						rgb += result;
						img.setRGB( x++, y, rgb );
						if( x >= img.getWidth() ) {
							x = 0;
							y++;
						}
						rgb = img.getRGB( x, y );
						rgb = rgb & mask;
						break;
				}
			}
			img.setRGB( x++, y, rgb );
			if( x >= img.getWidth() ) {
				x = 0;
				y++;
			}
		}
		return img;
	}


	private static byte[] extract( BufferedImage img ) {

		byte[] bytes = new byte[ img.getWidth() * img.getHeight() * 3 / 4 ];
		byte overflow = (byte) 0xFF;
		int count = 0;
		for( int y = 0; y < img.getHeight(); y++ ) {
			for( int x = 0; x < img.getWidth(); x++ ) {
				int rgb = img.getRGB( x, y );
				rgb = rgb & zeroMask;
				byte[] integer = ByteBuffer.allocate( 4 ).putInt( rgb ).array();
				byte tmp = 0;
				switch( count % 4 ) {
					case 0:
						integer[ 1 ] = (byte) ( ( integer[ 1 ] << 6 ) ^ fillMask1 );
						integer[ 2 ] = (byte) ( ( integer[ 2 ] << 4 ) ^ fillMask2 );
						integer[ 3 ] = (byte) ( ( integer[ 3 ] << 2 ) ^ fillMask3 );
						overflow = (byte) 0xFF;
						overflow = (byte) ( overflow & integer[ 1 ] );
						overflow = (byte) ( overflow & integer[ 2 ] );
						overflow = (byte) ( overflow & integer[ 3 ] );
						break;
					case 1:
						integer[ 1 ] = (byte) ( ( integer[ 1 ] ) ^ fillMask4 );
						integer[ 2 ] = (byte) ( ( integer[ 2 ] << 6 ) ^ fillMask1 );
						integer[ 3 ] = (byte) ( ( integer[ 3 ] << 4 ) ^ fillMask2 );
						overflow = (byte) ( overflow & integer[ 1 ] );
						tmp = overflow;
						overflow = (byte) 0xFF;
						overflow = (byte) ( overflow & integer[ 2 ] );
						overflow = (byte) ( overflow & integer[ 3 ] );
						break;
					case 2:
						integer[ 1 ] = (byte) ( ( integer[ 1 ] << 2 ) ^ fillMask3 );
						integer[ 2 ] = (byte) ( ( integer[ 2 ] ) ^ fillMask4 );
						integer[ 3 ] = (byte) ( ( integer[ 3 ] << 6 ) ^ fillMask1 );
						overflow = (byte) ( overflow & integer[ 1 ] );
						overflow = (byte) ( overflow & integer[ 2 ] );
						tmp = overflow;
						overflow = (byte) 0xFF;
						overflow = (byte) ( overflow & integer[ 3 ] );
						break;
					case 3:
						integer[ 1 ] = (byte) ( ( integer[ 1 ] << 4 ) ^ fillMask2 );
						integer[ 2 ] = (byte) ( ( integer[ 2 ] << 2 ) ^ fillMask3 );
						integer[ 3 ] = (byte) ( ( integer[ 3 ] ) ^ fillMask4 );
						overflow = (byte) ( overflow & integer[ 1 ] );
						overflow = (byte) ( overflow & integer[ 2 ] );
						overflow = (byte) ( overflow & integer[ 3 ] );
						tmp = overflow;
						overflow = (byte) 0xFF;
						break;
				}

				if( count % 4 != 0 ) {
					if( tmp == 0 ) {
						byte[] result = new byte[ ( count - 1 ) - Math.floorDiv( count, 4 ) ];
						System.arraycopy( bytes, 0, result, 0, ( count - 1 ) - Math.floorDiv( count, 4 ) );
						return result;
					} else {
						bytes[ ( count - 1 ) - Math.floorDiv( count, 4 ) ] = tmp;
					}
				}
				count++;
			}
		}
		return bytes;
	}
}
