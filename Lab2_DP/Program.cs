using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace SignatureCipher
{
	internal class Program
	{
		private static Byte _synchroLink = 0xFF; //255

		static void Main(string[] args)
		{
			Byte[] sourceBytes = File.ReadAllBytes("plain.txt"); // считываем исходные байты из файла
			Byte[] keyBytes = File.ReadAllBytes("key.txt"); // считываем байты ключа из файла

			Byte[] encodedBytes = EncodeBytes(sourceBytes, keyBytes); // кодируем байты
			File.WriteAllBytes("encryption.txt", encodedBytes); // сохраняем закодированные байты в файл

			Byte[] decodedBytes = DecodeBytes(encodedBytes, keyBytes); // декодируем байты
			File.WriteAllBytes("decryption.txt", decodedBytes); // сохраняем декодированные байты в файл
		}



		private static Byte[] EncodeBytes(Byte[] sourceBytes, Byte[] keyBytes)
		{
			String sourceBits = ConvertByteArrayToBitsString(sourceBytes); // конвертируем массив байтов в биты
			String keyBits = ConvertByteArrayToBitsString(keyBytes).Substring(8); // здесь тоже, но с помощью Substring() мы обрезаем первые 8 битов строки (потому что первый бит мы возьмём дальше)
			String resultBits = "";

			Byte currentByte = _synchroLink; // изначальный байт равен синхропосылке
			Byte keyByte = keyBytes[0]; // байт ключа изначально равен первому байту из массива ключа

			// проходим по всем исходным битам
			for (int i = 0; i < sourceBits.Length; i++) 
			{
				Byte xorValue = (Byte)(currentByte ^ keyByte);
				Byte oneBit = CalculateXorAllBits(xorValue);
				Byte inputBit = GetBitByChar(sourceBits[i]);  // берём текущий бит исходных данных

				Byte xorBitsResult = (Byte)(oneBit ^ inputBit);

				resultBits += (currentByte & 0x80) != 0 ? '1' : '0'; // здесь берём самый левый бит из B, и добавляем в результирующую строку
				currentByte <<= 1; // сдвигаем B влево на 1 бит
				currentByte |= xorBitsResult; // и в освободившееся место, в самый правй бит добавляем результат 
				keyByte <<= 1; // тут тоже избавляемся от самого левого бита
				keyByte |= GetBitByChar(keyBits[i]); // и в самый правый бит вставляем новый бит из исходного ключа
			}

			resultBits += ConvertByteToBitsString(currentByte); // так как исходные биты закончились, а в B ещё хранится 8 битов, которые мы не должны потерять, то просто добавляем их в конец результата
			return ConvertBitsStringToByteArray(resultBits); // конвертируем биты в байты и возвращаем
		}

		private static Byte[] DecodeBytes(Byte[] sourceBytes, Byte[] keyBytes)
		{
			String sourceBits = ConvertByteArrayToBitsString(sourceBytes);
			String keyBits = ConvertByteArrayToBitsString(keyBytes);
			String resultBits = "";

			sourceBits.Remove(sourceBits.Length - 8); 
			keyBits.Remove(keyBits.Length - 8);

			Byte currentByte = sourceBytes[sourceBytes.Length - 1]; // берём последний байт из массива (это B)
			Byte keyByte = keyBytes[keyBytes.Length - 1]; // берём последний байт из массива ключа (это K)

			for (int i = sourceBits.Length - 1; i >= 0; i--)
			{
				// извлекаем из B самый правый бит (в шифровании мы его добавляли)
				Byte inputBit = (Byte)(currentByte & 1);

				// перед тем как добавить бит в шифровании, мы сдвигали биты в B и K
				// снова их сдвигаем, но уже в обратном направлении вправо и после этого заполняем самый левый бит
				currentByte >>= 1;
				currentByte |= (Byte)(GetBitByChar(sourceBits[i]) << 7); // здесь берём из исходного потока данных бит и помещаем в самый левый бит B
				keyByte >>= 1;
				keyByte |= (Byte)(GetBitByChar(keyBits[i]) << 7); // здесь берём из исходного потока ключа бит и помещаем в самый левый бит K

				// снова B xor K
				Byte xorValue = (Byte)(currentByte ^ keyByte);
				Byte oneBit = CalculateXorAllBits(xorValue); // после чего считаем сумму каждого бита по модулю двух (xor)
				Byte xorBitsResult = (Byte)(oneBit ^ inputBit); // и чтобы получить исходный бит (исходный до шифрации), нужно ксорить первый бит B (который мы сохранили), и единичный бит после суммы

				resultBits += xorBitsResult; // добавляем этот бит в строку результата
			}

			// т.к. мы добавляли биты в обратном порядке, то должны их перевернуть
			// удаляем последние 8 бит - синхропосылка 
			resultBits = ReverseString(resultBits).Remove(resultBits.Length - 8);
			return ConvertBitsStringToByteArray(resultBits); // конвертируем биты в байты и возвращаем
		}

		private static String ReverseString(String sourceString)
		{
			Char[] characters = sourceString.ToCharArray(); // преобразуем строку в массив чаров
			Array.Reverse(characters); // реверс с помощью системного метода Array.Reverse()

			return new String(characters); // создаём новую строку из массива чаров
		}


		private static Byte CalculateXorAllBits(Byte byteValue)
		{
			Byte result = 0;
			for (int i = 0; i < 8; i++)
				result ^= (Byte)((byteValue >> i) & 1); //хор между собой

			return result;
		}

		private static Byte GetBitByChar(Char character)
		{
			return (Byte)(character == '1' ? 1 : 0);
		}


		private static Byte[] ConvertBitsStringToByteArray(String bitsString)
		{
			Byte[] byteArray = new Byte[bitsString.Length / 8]; // длина равна количество байт

			for (int i = 0; i < byteArray.Length; i++)
			{
				String currentByte = bitsString.Substring(i * 8, 8); 
				byteArray[i] = ConvertBitsStringToByte(currentByte); // преобразуем эти 8 бит в байт
			}

			return byteArray;
		}

		private static Byte ConvertBitsStringToByte(String bitsString)
		{
			Byte resultByte = 0;
			Byte mask = 0x80; // маска

			for (int i = 0; i < 8; i++)
			{ // считываем 8 символов строки
			  // если символ равен "1", то бит присутствует
			  // и с помощь побитовой операции ИЛИ, добавляем его к resultByte
				resultByte |= bitsString[i] == '1' ? mask : (Byte)0;
				mask >>= 1; // маску сдвигаем на один бит вправо
			}

			return resultByte;
		}

		private static String ConvertByteArrayToBitsString(Byte[] byteArray)
		{
			StringBuilder stringBuilder = new StringBuilder(); // позволяет оптимизированно складывать строки

			foreach (var currentByte in byteArray)
				stringBuilder.Append(ConvertByteToBitsString(currentByte));

			return stringBuilder.ToString(); // получаем результат сложения строк.
		}


		private static String ConvertByteToBitsString(Byte sourceByte)
		{
			String resultString = "";

			Byte mask = 0x80; // битовая маска 1000 0000
			while (mask != 0)
			{
			  // 13 & mask = [0000 1101] & [1000 0000] = [0000 0000] (равно 0)
			  // 13 & mask = [0000 1101] & [0000 1000] = [0000 1000] (не равно 0)
				resultString += (sourceByte & mask) != 0 ? "1" : "0";

				mask >>= 1; 
			}
			return resultString;
		}
	}
}