-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Waktu pembuatan: 26 Okt 2024 pada 15.39
-- Versi server: 10.4.32-MariaDB
-- Versi PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `virtual_assistant`
--

-- --------------------------------------------------------

--
-- Struktur dari tabel `articles`
--

CREATE TABLE `articles` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `images` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data untuk tabel `articles`
--

INSERT INTO `articles` (`id`, `user_id`, `title`, `content`, `images`, `created_at`, `updated_at`) VALUES
(1, 3, 'Diabetes', 'Lorem ipsum dolor sit amet', '3_mapping.png', '2024-10-21 14:36:31', '2024-10-21 14:36:31');

-- --------------------------------------------------------

--
-- Struktur dari tabel `rumah_sakit`
--

CREATE TABLE `rumah_sakit` (
  `id` int(11) NOT NULL,
  `kode_rs` int(20) NOT NULL,
  `nama_rumah_sakit` varchar(255) NOT NULL,
  `jenis_rs` varchar(55) NOT NULL,
  `kelas_rs` varchar(10) NOT NULL,
  `pemilik` varchar(30) NOT NULL,
  `total_ranjang` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data untuk tabel `rumah_sakit`
--

INSERT INTO `rumah_sakit` (`id`, `kode_rs`, `nama_rumah_sakit`, `jenis_rs`, `kelas_rs`, `pemilik`, `total_ranjang`) VALUES
(1, 0, 'nama_rumah_sakit', 'jenis_rs', 'kelas_rs', 'pemilik', 0),
(2, 3371144, 'RSUD Budi Rahayu', 'RSU', 'D', 'Pemkot', 35),
(3, 3372201, 'RSU Surakarta BKPM', 'RSU', 'D', 'Pemkot', 52),
(4, 3320046, 'RS PKU Aisyiyah Jepara', 'RSU', 'D', 'Organisasi Islam', 20),
(5, 3374373, 'RS Gigi dan Mulut Unimus', 'RSK GM', 'C', 'Swasta', 4),
(6, 3372242, 'RS Onkologi Solo', 'RSK KANKER', 'C', 'Swasta', 17),
(7, 3324040, 'RSU Charlie Hospital', 'RSU', 'D', 'Perorangan', 45),
(8, 3329113, 'RS Harapan Sehat Bumiayu', 'RSU', 'D', 'Perusahaan', 40),
(9, 3374372, 'RS Islam Gigi dan Mulut Sultan Agung', 'RSK GM', 'B', 'Swasta', 5),
(10, 3372241, 'RS \"JIH\" Solo', 'RSU', 'C', 'Swasta', 104),
(11, 3327048, 'RS Harapan Sehat Pemalang', 'RSU', 'D', 'Swasta', 98),
(12, 3372240, 'RSU Umum Daerah Bung Karno Kota Surakarta', 'RSU', 'C', 'Pemkot', 123),
(13, 3328082, 'RS Hawari Essa', 'RSU', 'D', 'Perorangan', 36),
(14, 3329112, 'RS Harapan Sehat Jatibarang', 'RSU', 'D', 'Perusahaan', 43),
(15, 3328081, 'RS Harapan Sehat Slawi', 'RSU', 'D', 'Swasta', 98),
(16, 3301114, 'RS Umum Aghisna Medika Sidareja', 'RSU', 'D', 'Swasta', 50),
(17, 3304035, 'RS Umum PKU Muhammadiyah Banjarnegara', 'RSU', 'D', 'Organisasi Islam', 46),
(18, 3372239, 'RS Gigi dan Mulut Soelastri', 'RSK GM', 'C', 'Perorangan', 3),
(19, 3308021, 'RS Umum Syubbanul Wathon', 'RSU', 'C', 'Perusahaan', 39),
(20, 3310416, 'RSU PKU Muhammadiyah Delanggu', 'RSU', 'D', 'Organisasi Islam', 172),
(21, 3314097, 'RS Umum Saras Ibnu Sina Sukowati', 'RSU', 'D', 'Perusahaan', 67),
(22, 3374371, 'Siloam Hospitals Semarang', 'RSU', 'D', 'Swasta', 20),
(23, 3306112, 'RS Umum Ananda Purworejo', 'RSU', 'D', 'Swasta', 22),
(24, 3317027, 'RS Bhina Bhakti Husada', 'RSU', 'C', 'Perusahaan', 97),
(25, 3301112, 'RSU Raffa Majenang', 'RSU', 'D', 'Swasta', 50),
(26, 3314096, 'RS Umum Rizky Amalia', 'RSU', 'D', 'Perusahaan', 40),
(27, 3375075, 'RS Umum Hermina Pekalongan', 'RSU', 'D', 'Perusahaan', 28),
(28, 3306111, 'RS Amanah Umat Purworejo', 'RSU', 'D', 'Perusahaan', 94),
(29, 3372238, 'RS PKU Muhammadiyah Sampangan Surakarta', 'RSU', 'D', 'Organisasi Islam', 18),
(30, 3302232, 'RS Hermina Purwokerto', 'RSU', 'C', 'Perusahaan', 59),
(31, 3311230, 'RS PKU Muhammadiyah Kartasura', 'RSU', 'D', 'Organisasi Islam', 53),
(32, 3309132, 'RS Umum Natalia', 'RSU', 'D', 'Swasta', 40),
(33, 3310425, 'RS PKU Muhammadiyah Pedan', 'RSU', 'D', 'Organisasi Islam', 0),
(34, 3311229, 'RS Umum Indriati', 'RSU', 'C', 'Swasta', 140),
(35, 3325039, 'RS Umum Daerah Limpung', 'RSU', 'D', 'Pemkab', 44),
(36, 3309135, 'RS Indriati Boyolali', 'RSU', 'D', 'Swasta', 44),
(37, 3305120, 'RS Umum Daerah Prembun', 'RSU', 'C', 'Pemkab', 96),
(38, 3303101, 'RS Umum Siaga Medika Purbalingga', 'RSU', 'C', 'Swasta', 77),
(39, 3326051, 'RS Ibu dan Anak Aisyiyah Pekajangan Pekalongan', 'RSIA', 'C', 'Organisasi Islam', 33),
(40, 3318113, 'RS Umum As-Suyuthiyyah', 'RSU', 'D', 'Swasta', 46),
(41, 3327047, 'RS Umum Muhammadiyah Mardhatillah', 'RSU', 'D', 'Organisasi Islam', 74),
(42, 3311228, 'RS Umum Universitas Sebelas Maret', 'RSU', 'C', 'Kementerian Lain', 100),
(43, 3306110, 'RS Umum Budi Sehat Purworejo', 'RSU', 'D', 'Swasta', 47),
(44, 3322073, 'RS Umum Kusuma Ungaran', 'RSU', 'D', 'Perusahaan', 68),
(45, 3306109, 'RS Umum Islam Purworejo', 'RSU', 'D', 'Organisasi Islam', 67),
(46, 3374369, 'RS Ibu dan Anak Ananda Pasar Ace', 'RSIA', 'C', 'Perusahaan', 23),
(47, 3318111, 'RS Umum Sebening Kasih', 'RSU', 'D', 'Swasta', 42),
(48, 3310421, 'RS Umum Daerah Bagas Waras', 'RSU', 'C', 'Pemkab', 145),
(49, 3318110, 'RS Umum Fastabiq Sehat PKU Muhammadiyah Pati', 'RSU', 'D', 'Organisasi Islam', 97),
(50, 3307051, 'RS Umum  PKU Muhammadiyah Wonosobo', 'RSU', 'C', 'Swasta', 105),
(51, 3329109, 'RS Umum Amanah Mahmudah', 'RSU', 'D', 'Perusahaan', 40),
(52, 3308019, 'RS Umum Padma Lalita', 'RSU', 'D', 'Swasta', 42),
(53, 3310419, 'RS Umum Mitra Keluarga Husada Klaten', 'RSU', 'D', 'Perusahaan', 57),
(54, 3324038, 'RS Umum Baitul Hikmah', 'RSU', 'D', 'Perusahaan', 47),
(55, 3311225, 'RS Umum PKU Muhammadiyah Sukoharjo', 'RSU', 'C', 'Organisasi Islam', 97),
(56, 3372236, 'RS Umum Hermina Solo', 'RSU', 'C', 'Swasta', 67),
(57, 3301109, 'RSU Afdila Cilacap', 'RSU', 'D', 'Swasta', 88),
(58, 3374367, 'RS Umum Nasional Diponegoro', 'RSU', 'C', 'Kementerian Lain', 272),
(59, 3310418, 'RS Umum PKU Muhammadiyah Jatinom Klaten', 'RSU', 'D', 'Organisasi Islam', 62),
(60, 3374366, 'RS Umum Columbia Asia Semarang', 'RSU', 'B', 'Perusahaan', 91),
(61, 3374365, 'RS Umum Hermina Banyumanik Semarang', 'RSU', 'C', 'Perusahaan', 70),
(62, 3310417, 'RS Umum Islam Cawas Klaten', 'RSU', 'D', 'Swasta', 54),
(63, 3301108, 'RS Umum Aghisna Medika Kroya', 'RSU', 'D', 'Swasta', 50),
(64, 3329108, 'RS Umum Alam Medica', 'RSU', 'D', 'Swasta', 74),
(65, 3312309, 'RS Umum Astrini', 'RSU', 'D', 'Perusahaan', 48),
(66, 3308018, 'RS Umum N21 - Gemilang', 'RSU', 'D', 'Perusahaan', 43),
(67, 3308017, 'RS Umum Aisyiyah Muntilan', 'RSU', 'D', 'Swasta', 95),
(68, 3302229, 'RS Umum Dadi Keluarga', 'RSU', 'C', 'Swasta', 114),
(69, 3302228, 'RS Khusus Gigi dan Mulut Univ. Jenderal Soedirman', 'RSK GM', 'B', 'Kementerian Lain', 9),
(70, 3329105, 'RS Ibu dan Anak Permata Insani', 'RSIA', 'C', 'Swasta', 23),
(71, 3328079, 'RS Ibu dan Anak Pala Raya', 'RSIA', 'C', 'Swasta', 71),
(72, 3305118, 'RS Umum Muhammadiyah Kutowinangun', 'RSU', 'D', 'Organisasi Islam', 32),
(73, 3372235, 'RS Khusus Mata Solo', 'RSK Mata', 'C', 'Perusahaan', 19),
(74, 3375074, 'RS Umum  ARO', 'RSU', 'D', 'Swasta', 44),
(75, 3305117, 'RS Umum PKU Muhammadiyah Petanahan Kebumen', 'RSU', 'D', 'Organisasi Islam', 35),
(76, 3309131, 'RS Umum Islam Banyubening Boyolali', 'RSU', 'D', 'Swasta', 60),
(77, 3312308, 'RS Umum Mulia Hati Wonogiri', 'RSU', 'D', 'Perusahaan', 47),
(78, 3313056, 'RS Umum Mojosongo 2', 'RSU', 'D', 'Swasta', 27),
(79, 3327046, 'RS Ibu dan Anak Siti Aminah Pemalang', 'RSIA', 'C', 'Swasta', 0),
(80, 3314092, 'RS Umum Islam Yakssi Gemolong', 'RSU', 'D', 'Perusahaan', 61),
(81, 3324037, 'RS Umum Muhammadiyah Darul Istiqomah', 'RSU', 'D', 'Organisasi Islam', 71),
(82, 3303099, 'RS Ibu dan Anak Ummu Hani', 'RSIA', 'C', 'Perusahaan', 45),
(83, 3306108, 'RS Ibu dan Anak Kasih Ibu Purworejo', 'RSIA', 'C', 'Organisasi Sosial', 24),
(84, 3313055, 'RS Umum Jafar Medika Karanganyar', 'RSU', 'D', 'Organisasi Sosial', 38),
(85, 3306106, 'RS Umum Purwa Husada', 'RSU', 'D', 'Perusahaan', 23),
(86, 3301107, 'RS Umum Santa Maria Cilacap', 'RSU', 'D', 'Organisasi Katholik', 67),
(87, 3309129, 'RS Umum Hidayah Boyolali', 'RSU', 'D', 'Swasta', 104),
(88, 3315059, 'RS Umum Islam Purwodadi', 'RSU', 'D', 'Organisasi Islam', 57),
(89, 3302227, 'RS Umum Medika Lestari Banyumas', 'RSU', 'D', 'Swasta', 71),
(90, 3318109, 'RS Umum  Budi Agung Pati', 'RSU', 'D', 'Swasta', 47),
(91, 3327045, 'RS Umum Prima Medika', 'RSU', 'C', 'Swasta', 79),
(92, 3301106, 'RS Umum Duta Mulya', 'RSU', 'D', 'Perusahaan', 43),
(93, 3302226, 'RS Ibu dan Anak Budhi Asih', 'RSIA', 'C', 'Organisasi Sosial', 17),
(94, 3302225, 'RS Khusus Bedah Mitra Ariva', 'RSK BEDAH', 'C', 'Organisasi Sosial', 25),
(95, 3373092, 'RS Bersalin Mutiara Bunda  Salatiga', 'RSIA', 'C', 'Perorangan', 17),
(96, 3313054, 'RS Umum Indo Sehat Karangayar', 'RSU', 'D', 'Swasta', 43),
(97, 3322072, 'RS Ibu dan Anak Plamongan Indah', 'RSIA', 'C', 'Perusahaan', 24),
(98, 3316063, 'RS Umum PKU Muhammdiyah Blora', 'RSU', 'D', 'Swasta', 36),
(99, 3319023, 'RS Ibu dan Anak Harapan Bunda', 'RSIA', 'C', 'Swasta', 34),
(100, 3306105, 'RS Ibu dan Anak Permata', 'RSIA', 'C', 'Perusahaan', 25),
(101, 3375073, 'RS Umum H. A. Zaky Djunaid', 'RSU', 'D', 'Swasta', 65),
(102, 3315058, 'RS Umum Enggal Waras', 'RSU', 'D', 'Organisasi Sosial', 32),
(103, 3319022, 'RS Umum Kumala Siwimijen Kudus', 'RSU', 'D', 'Organisasi Sosial', 97),
(104, 3375072, 'RS Umum Anugerah Pekalongan', 'RSU', 'D', 'Swasta', 60),
(105, 3327044, 'RS Umum Siaga Medika Pemalang', 'RSU', 'C', 'Swasta', 209),
(106, 3329103, 'RS Umum Islami Mutiara Bunda', 'RSU', 'D', 'Perusahaan', 91),
(107, 3329102, 'RS Umum Daerah Bumiayu', 'RSU', 'D', 'Pemkab', 92),
(108, 3314090, 'RS Umum PKU Muhammadiyah Sragen', 'RSU', 'D', 'Swasta', 52),
(109, 3373091, 'RS Umum Sejahtera Bhakti', 'RSU', 'D', 'Swasta', 25),
(110, 3321034, 'RS Umum Pelita Anugerah', 'RSU', 'C', 'Swasta', 97),
(111, 3312307, 'RS Fitri Candra', 'RSU', 'D', 'Perusahaan', 56),
(112, 3319021, 'RS Umum  Aisyiyah Kudus', 'RSU', 'D', 'Swasta', 104),
(113, 3374091, 'RS Umum Bhayangkara Semarang', 'RSU', 'C', 'POLRI', 91),
(114, 3325037, 'RS Umum Qim', 'RSU', 'C', 'Swasta', 160),
(115, 3322034, 'RS Umum Ken Saras', 'RSU', 'C', 'Perusahaan', 177),
(116, 3329101, 'RS Umum Dera As-Syifa', 'RSU', 'D', 'Swasta', 71),
(117, 3303097, 'RS Umum Daerah Panti Nugroho', 'RSU', 'D', 'Pemkab', 51),
(118, 3305023, 'RS Umum Permata Medika Kebumen', 'RSU', 'D', 'Swasta', 88),
(119, 3328035, 'RS Umum Daerah Suradadi', 'RSU', 'C', 'Pemkab', 80),
(120, 3328078, 'RS Umum Adella', 'RSU', 'D', 'Swasta', 29),
(121, 3320089, 'RS Umum PKU Muhammadiyah Mayong', 'RSU', 'D', 'Organisasi Islam', 104),
(122, 3312021, 'RS Umum Maguan Husada', 'RSU', 'D', 'Perusahaan', 60),
(123, 3313053, 'RS Umum Jati Husada', 'RSU', 'D', 'Perorangan', 84),
(124, 3314089, 'RS Umum Daerah dr. Soeratno Gemolong', 'RSU', 'C', 'Pemkab', 146),
(125, 3328042, 'RSU Mitra Keluarga Tegal', 'RSU', 'C', 'Swasta', 84),
(126, 3319043, 'RS Umum  Nurussyifa', 'RSU', 'D', 'Organisasi Islam', 34),
(127, 3317026, 'RS Umum Islam Arafah', 'RSU', 'D', 'Organisasi Islam', 71),
(128, 3314078, 'RS Ibu dan Anak Restu Ibu', 'RSIA', 'C', 'Organisasi Sosial', 41),
(129, 3309128, 'RS Umum Asy-Syifa Sambi', 'RSU', 'D', 'Organisasi Islam', 101),
(130, 3306023, 'RS Umum  Aisyiyah', 'RSU', 'D', 'Organisasi Islam', 30),
(131, 3302074, 'RS Umum An Ni\'mah', 'RSU', 'D', 'Perusahaan', 57),
(132, 3304032, 'RS Umum Islam Banjarnegara', 'RSU', 'D', 'Organisasi Sosial', 142),
(133, 3302063, 'RS Khusus Bedah Jatiwinangun', 'RSK BEDAH', 'C', 'Swasta', 50),
(134, 3374054, 'RS Umum Permata Medika', 'RSU', 'C', 'Swasta', 125),
(135, 3328011, 'RS Umum Daerah dr. Soeselo Slawi Kabupaten Tegal', 'RSU', 'B', 'Pemkab', 343),
(136, 3318108, 'RS Umum Keluarga Sehat', 'RSU', 'C', 'Organisasi Sosial', 198),
(137, 3313042, 'RS Ibu dan Anak Dian Pertiwi', 'RSIA', 'C', 'Swasta', 25),
(138, 3311027, 'RS Khusus Bedah Karima Utama', 'RSK BEDAH', 'C', 'Swasta', 94),
(139, 3305114, 'RS Umum Purwogondo', 'RSU', 'D', 'Organisasi Sosial', 74),
(140, 3302174, 'RS Ibu dan Anak Bunda Arif', 'RSIA', 'C', 'Organisasi Sosial', 41),
(141, 3302121, 'RS Ibu dan Anak Amanah', 'RSIA', 'C', 'Organisasi Sosial', 16),
(142, 3302052, 'RS Khusus Bedah Orthopedi', 'RSK Orthopedi', 'C', 'Swasta', 47),
(143, 3376093, 'RS Ibu dan Anak Kasih Ibu Tegal', 'RSIA', 'C', 'Organisasi Sosial', 25),
(144, 3376082, 'RS Umum Islam Harapan Anda', 'RSU', 'B', 'Organisasi Islam', 302),
(145, 3376034, 'RS Umum Tk.IV Tegal', 'RSU', 'D', 'TNI AD', 49),
(146, 3376023, 'RS Umum  Mitra Siaga', 'RSU', 'C', 'Swasta', 139),
(147, 3376012, 'RS Umum Daerah Kardinah', 'RSU', 'B', 'Pemkot', 430),
(148, 3375071, 'RS Umum Karomah Holistic', 'RSU', 'D', 'Swasta', 42),
(149, 3375033, 'RS Umum Siti Khodijah', 'RSU', 'C', 'Organisasi Islam', 101),
(150, 3375022, 'RS Umum Budi Rahayu', 'RSU', 'C', 'Organisasi Protestan', 144),
(151, 3326011, 'RS Umum Daerah Kraton Kab. Pekalongan', 'RSU', 'B', 'Pemkab', 184),
(152, 3374353, 'RS Ibu dan Anak Kusuma Pradja', 'RSIA', 'C', 'Swasta', 40),
(153, 3374342, 'RS Umum Daerah K.R.M.T  Wongsonegoro', 'RSU', 'B', 'Pemkot', 367),
(154, 3374331, 'RS Umum Banyumanik', 'RSU', 'D', 'Swasta', 36),
(155, 3374316, 'RS Ibu dan Anak Gunung Sawo', 'RSIA', 'C', 'Organisasi Sosial', 20),
(156, 3374284, 'RS Ibu dan Anak Bunda Semarang', 'RSIA', 'C', 'Organisasi Sosial', 25),
(157, 3374273, 'RS Ibu dan Anak Anugerah', 'RSIA', 'C', 'Swasta', 21),
(158, 3374240, 'RS Panti Wilasa', 'RSU', 'C', 'Organisasi Protestan', 165),
(159, 3374203, 'RS Umum Bhayangkara Akpol Semarang', 'RSU', 'D', 'POLRI', 28),
(160, 3374145, 'RS Umum Hermina Pandanaran', 'RSU', 'C', 'Swasta', 70),
(161, 3374134, 'RS Umum Daerah Tugurejo Semarang', 'RSU', 'B', 'Pemprop', 350),
(162, 3374123, 'RS Jiwa Daerah  Dr. Amino  Gondohutomo', 'RSK Jiwa', 'A', 'Pemprop', 336),
(163, 3374112, 'RS Umum Panti Wilasa Citarum', 'RSU', 'C', 'Organisasi Protestan', 175),
(164, 3374080, 'RS Umum Roemani Muhammadiyah', 'RSU', 'C', 'Organisasi Islam', 217),
(165, 3374076, 'RS Umum Sultan Agung Semarang', 'RSU', 'B', 'Organisasi Islam', 368),
(166, 3374065, 'RS Umum Tk.III Bhakti Wira Tamtama  Smg', 'RSU', 'C', 'TNI AD', 126),
(167, 3374043, 'RS Umum Telogorejo Semarang', 'RSU', 'B', 'Organisasi Sosial', 263),
(168, 3374032, 'RS Umum William Booth', 'RSU', 'C', 'Organisasi Sosial', 71),
(169, 3374021, 'RS Umum St. Elisabeth Semarang', 'RSU', 'B', 'Organisasi Katholik', 296),
(170, 3374010, 'RS Umum Pusat Dr. Kariadi', 'RSU', 'A', 'Kemkes', 998),
(171, 3373090, 'RS Umum Puri Asih', 'RSU', 'C', 'Swasta', 114),
(172, 3373042, 'RS Paru Dr. Ario Wirawan', 'RSK PARU', 'A', 'Kemkes', 177),
(173, 3373020, 'RS Umum Tk. IV 04.07.03 dr. Asmir', 'RSU', 'C', 'TNI AD', 118),
(174, 3373016, 'RS Umum Daerah Salatiga', 'RSU', 'B', 'Pemkot', 246),
(175, 3372234, 'RS Umum Daerah Kota Surakarta', 'RSU', 'C', 'Pemkot', 113),
(176, 3372191, 'RS Umum Triharsi', 'RSU', 'D', 'Organisasi Sosial', 28),
(177, 3372165, 'RS Umum Kasih Ibu', 'RSU', 'B', 'Organisasi Sosial', 168),
(178, 3372132, 'RS Umum Islam Kustati', 'RSU', 'C', 'Organisasi Islam', 191),
(179, 3372096, 'RS Umum PKU Muhammadiyah Surakarta', 'RSU', 'B', 'Organisasi Islam', 296),
(180, 3372074, 'RS Umum Panti Waluyo', 'RSU', 'C', 'Organisasi Sosial', 129),
(181, 3372063, 'RS Orthopedi Prof. Dr. R. Soeharso', 'RSK Orthopedi', 'A', 'Kemkes', 138),
(182, 3372052, 'RS Jiwa Daerah Surakarta', 'RSK Jiwa', 'A', 'Pemprop', 297),
(183, 3372041, 'RS Umum Brayat Minulya', 'RSU', 'C', 'Organisasi Sosial', 92),
(184, 3372030, 'RS Umum Tk IV Slamet Riyadi  Surakarta', 'RSU', 'C', 'TNI AD', 94),
(185, 3372026, 'RS Umum Dr. Oen', 'RSU', 'B', 'Organisasi Sosial', 199),
(186, 3372015, 'RS Umum Daerah Dr. Moewardi Surakarta', 'RSU', 'A', 'Pemprop', 653),
(187, 3371142, 'RS Umum Islam Magelang', 'RSU', 'D', 'Organisasi Sosial', 61),
(188, 3371131, 'RS Umum Harapan', 'RSU', 'C', 'Swasta', 80),
(189, 3371105, 'RS Ibu dan Anak Gladiool', 'RSIA', 'C', 'Organisasi Sosial', 15),
(190, 3371084, 'RS Umum Lestari Raharja', 'RSU', 'D', 'Organisasi Sosial', 57),
(191, 3371040, 'RS Jiwa Prof. Dr. Soerojo', 'RSK Jiwa', 'A', 'Kemkes', 439),
(192, 3371025, 'RS Umum Tk II Dr. Soedjono', 'RSU', 'B', 'TNI AD', 216),
(193, 3371014, 'RS Umum Daerah Tidar', 'RSU', 'B', 'Pemkot', 276),
(194, 3329078, 'RS Umum Bhakti Asih', 'RSU', 'C', 'Swasta', 171),
(195, 3329067, 'RS Umum Dedy Jaya', 'RSU', 'D', 'Swasta', 46),
(196, 3329056, 'RS Umum Muhammadiyah Siti Aminah', 'RSU', 'D', 'Organisasi Islam', 89),
(197, 3329045, 'RS Umum Siti Asiyah', 'RSU', 'D', 'Organisasi Islam', 60),
(198, 3329012, 'RS Umum Daerah Brebes', 'RSU', 'B', 'Pemkab', 373),
(199, 3328055, 'RSU Islam PKU Muhammadiyah', 'RSU', 'C', 'Organisasi Sosial', 188),
(200, 3327043, 'RS Umum Islam Al-Ikhlas', 'RSU', 'D', 'Organisasi Islam', 65),
(201, 3327032, 'RS Umum Islam Moga', 'RSU', 'D', 'Organisasi Islam', 52),
(202, 3327021, 'RS Umum Santa Maria Pemalang', 'RSU', 'C', 'Organisasi Katholik', 127),
(203, 3327010, 'RS Umum Daerah Dr. M Ashari Pemalang', 'RSU', 'C', 'Pemkab', 263),
(204, 3326049, 'RS Umum Daerah Bendan Kota  Pekalongan', 'RSU', 'C', 'Pemkot', 203),
(205, 3326038, 'RS Umum Daerah Kajen  Kab.Pekalongan', 'RSU', 'C', 'Pemkab', 168),
(206, 3326016, 'RS Umum Islam PKU Muhammadiyah Pekajangan', 'RSU', 'C', 'Organisasi Islam', 140),
(207, 3325026, 'RS Umum Bhakti Waluyo', 'RSU', 'D', 'Organisasi Sosial', 55),
(208, 3325015, 'RS Umum Daerah Kab. Batang', 'RSU', 'C', 'Pemkab', 217),
(209, 3324036, 'RS Umum Islam Kendal', 'RSU', 'C', 'Organisasi Islam', 184),
(210, 3324014, 'RS Umum Daerah  Dr. H. Soewondo  Kendal', 'RSU', 'B', 'Pemkab', 235),
(211, 3323050, 'RS Umum PKU Muhammadiyah Temanggung', 'RSU', 'C', 'Organisasi Islam', 136),
(212, 3323046, 'RS Umum Gunung Sawo Kab. Temanggung', 'RSU', 'D', 'Organisasi Sosial', 40),
(213, 3323024, 'RS Umum Ngesti Waluyo', 'RSU', 'C', 'Organisasi Protestan', 140),
(214, 3323013, 'RS Umum Daerah Djojonegoro  Temanggung', 'RSU', 'B', 'Pemkab', 318),
(215, 3322071, 'RS Umum Bina Kasih', 'RSU', 'D', 'Organisasi Sosial', 55),
(216, 3322023, 'RS Umum Daerah Ungaran', 'RSU', 'C', 'Pemkab', 183),
(217, 3322012, 'RS Umum Daerah Ambarawa', 'RSU', 'C', 'Pemkab', 250),
(218, 3321033, 'RS Umum Islam NU Demak', 'RSU', 'D', 'Organisasi Islam', 115),
(219, 3321011, 'RS Umum Daerah Sunan Kalijaga', 'RSU', 'C', 'Pemkab', 294),
(220, 3320043, 'RS Umum Graha Husada', 'RSU', 'D', 'Organisasi Sosial', 87),
(221, 3320032, 'RS Umum Sultan Hadlirin Jepara', 'RSU', 'C', 'Organisasi Islam', 123),
(222, 3320021, 'RS Umum Daerah Kelet Provinsi Jawa Tengah', 'RSU', 'C', 'Pemprop', 197),
(223, 3320010, 'RS Umum Daerah R. A. Kartini', 'RSU', 'B', 'Pemkab', 362),
(224, 3319102, 'RS Umum Bantuan Kudus', 'RSU', 'D', 'TNI AD', 50),
(225, 3319091, 'RS Ibu dan Anak Permata Hati', 'RSIA', 'C', 'Organisasi Sosial', 28),
(226, 3319080, 'RS Umum  Islam Sunan Kudus', 'RSU', 'C', 'Organisasi Islam', 179),
(227, 3319032, 'RS Umum Mardi Rahayu', 'RSU', 'B', 'Organisasi Sosial', 275),
(228, 3319010, 'RS Umum Daerah dr. Loekmono Hadi', 'RSU', 'B', 'Pemkab', 379),
(229, 3318097, 'RS Umum Bantuan Pati', 'RSU', 'D', 'TNI AD', 15),
(230, 3318086, 'RS Umum Daerah Kayen Pati', 'RSU', 'C', 'Pemkab', 84),
(231, 3318075, 'RS Umum Mitra Bangsa Pati', 'RSU', 'C', 'Organisasi Sosial', 117),
(232, 3318064, 'RS Umum Islam Pati', 'RSU', 'C', 'Organisasi Islam', 102),
(233, 3318016, 'RS Umum Daerah RAA Soewondo', 'RSU', 'B', 'Pemkab', 352),
(234, 3317015, 'RS Umum Daerah dr. R. Soetrasno  Rembang', 'RSU', 'C', 'Pemkab', 226),
(235, 3316062, 'RS Umum Bantuan Blora', 'RSU', 'D', 'TNI AD', 47),
(236, 3316051, 'RS Umum PKU Muhammadiyah Cepu', 'RSU', 'D', 'Organisasi Sosial', 96),
(237, 3316040, 'RS Umum Permata Blora', 'RSU', 'D', 'Organisasi Sosial', 61),
(238, 3316025, 'RS Umum Daerah Dr. R. Soeprapto Cepu', 'RSU', 'C', 'Pemkab', 108),
(239, 3316014, 'RS Umum Daerah Dr. R. Soetijono Blora', 'RSU', 'C', 'Pemkab', 138),
(240, 3315057, 'RS Umum Habibullah', 'RSU', 'D', 'Organisasi Sosial', 49),
(241, 3315046, 'RS Umum Muhammadiyah Gubug', 'RSU', 'D', 'Organisasi Islam', 95),
(242, 3315035, 'RS Umum Permata Bunda', 'RSU', 'C', 'Organisasi Sosial', 157),
(243, 3315024, 'RS Umum Panti Rahayu', 'RSU', 'C', 'Organisasi Sosial', 177),
(244, 3315013, 'RS Umum Daerah Dr. R.Soedjati  Soemodiardjo', 'RSU', 'B', 'Pemkab', 403),
(245, 3314067, 'RS Umum Assalam', 'RSU', 'D', 'Perusahaan', 81),
(246, 3314056, 'RS Umum Islam Amal Sehat Sragen', 'RSU', 'C', 'Organisasi Islam', 95),
(247, 3314045, 'RS Umum Sarila Husada', 'RSU', 'C', 'Organisasi Sosial', 107),
(248, 3314023, 'RS Umum Mardi Lestari Sragen', 'RSU', 'D', 'Organisasi Sosial', 91),
(249, 3314012, 'RS Umum Daerah dr. Soehadi Prijonegoro', 'RSU', 'B', 'Pemkab', 280),
(250, 3313033, 'RS Umum PKU Muhammadiyah Karang Anyar', 'RSU', 'C', 'Organisasi Islam', 145),
(251, 3313022, 'RS Umum Lanuma Adi Soemarmo', 'RSU', 'D', 'TNI AU', 43),
(252, 3313011, 'RS Umum Daerah Karanganyar', 'RSU', 'C', 'Pemkab', 353),
(253, 3312306, 'RS Umum  Amal Sehat', 'RSU', 'C', 'Swasta', 107),
(254, 3312295, 'RS Umum Medika Mulya', 'RSU', 'C', 'Swasta', 88),
(255, 3312284, 'RS Umum Muhammadiyah Selogiri', 'RSU', 'D', 'Organisasi Islam', 57),
(256, 3312273, 'RS Umum Marga Husada', 'RSU', 'D', 'Swasta', 53),
(257, 3312010, 'RS Umum Daerah Dr. Soediran Mangun  Sumarso Wonogi', 'RSU', 'B', 'Pemkab', 301),
(258, 3311224, 'RS Umum Dr. Oen Solo Baru', 'RSU', 'C', 'Organisasi Sosial', 154),
(259, 3311213, 'RS Umum Nirmala Suri', 'RSU', 'D', 'Organisasi Sosial', 50),
(260, 3311016, 'RS Umum Daerah Ir. Soekarno Kabupaten Sukoharjo', 'RSU', 'B', 'Pemkab', 185),
(261, 3310405, 'RS Khusus Bedah Diponegoro', 'RSK BEDAH', 'C', 'Organisasi Sosial', 61),
(262, 3310395, 'RS Umum Cakra Husada', 'RSU', 'D', 'Organisasi Sosial', 106),
(263, 3310384, 'RS Umum Islam Klaten', 'RSU', 'B', 'Organisasi Islam', 249),
(264, 3310052, 'RS Ibu dan Anak Aisyiah', 'RSIA', 'C', 'Organisasi Islam', 82),
(265, 3310026, 'RS Jiwa Daerah Dr. RM. Soedjarwadi', 'RSK Jiwa', 'A', 'Pemprop', 196),
(266, 3310015, 'RS Umum Pusat Dr. Soeradji Tirtonegoro', 'RSU', 'A', 'Kemkes', 420),
(267, 3309107, 'RS Umum Daerah Simo', 'RSU', 'D', 'Pemkab', 60),
(268, 3309096, 'RS Umum Daerah Waras Wiris', 'RSU', 'D', 'Pemkab', 60),
(269, 3309085, 'RS Umum  Karanggede Sisma Medika', 'RSU', 'D', 'Swasta', 57),
(270, 3309074, 'RS Umum Umi Barokah', 'RSU', 'D', 'Organisasi Sosial', 52),
(271, 3309063, 'RS Umum PKU Aisyiyah Boyolali', 'RSU', 'D', 'Organisasi Islam', 137),
(272, 3309041, 'RS Umum Dr. Oen Sawit', 'RSU', 'D', 'Organisasi Sosial', 27),
(273, 3309015, 'RS Umum Daerah Pandan Arang Boyolali', 'RSU', 'C', 'Pemkab', 218),
(274, 3308014, 'RS Umum Daerah Muntilan Kab. Magelang', 'RSU', 'C', 'Pemkab', 154),
(275, 3307050, 'RS Umum Islam Wonosobo', 'RSU', 'C', 'Organisasi Islam', 116),
(276, 3307035, 'RS Ibu dan Anak Adina', 'RSIA', 'C', 'Organisasi Sosial', 25),
(277, 3307013, 'RS Umum Setjonegoro Wonosobo', 'RSU', 'C', 'Pemkab', 163),
(278, 3306104, 'RS Umum Palang Biru Kutoarjo', 'RSU', 'C', 'Organisasi Sosial', 124),
(279, 3306082, 'RS Umum Panti Waluyo Yakkum Purworejo', 'RSU', 'D', 'Organisasi Sosial', 50),
(280, 3306012, 'RS Umum Daerah Dr. Tjitrowardojo Purworejo', 'RSU', 'B', 'Pemkab', 269),
(281, 3305103, 'RS Umum PKU Muhammadiyah Sruweng', 'RSU', 'C', 'Organisasi Islam', 98),
(282, 3305092, 'RS Umum Purbowangi', 'RSU', 'D', 'Organisasi Sosial', 51),
(283, 3305081, 'RS Umum Wijayakusuma', 'RSU', 'D', 'Organisasi Sosial', 61),
(284, 3305066, 'RS Umum PKU Muhamadiyah Gombong', 'RSU', 'C', 'Organisasi Islam', 242),
(285, 3305033, 'RS Umum Palang Biru Gombong', 'RSU', 'D', 'Organisasi Sosial', 95),
(286, 3305011, 'RS Umum Daerah dr. Soedirman Kabupaten Kebumen', 'RSU', 'C', 'Pemkab', 254),
(287, 3304021, 'RS Umum Emmanuel', 'RSU', 'C', 'Organisasi Protestan', 173),
(288, 3304010, 'RS Umum Daerah Hj. Anna Lasmanah Banjarnegara', 'RSU', 'C', 'Pemkab', 203),
(289, 3303075, 'RS Umum Harapan Ibu', 'RSU', 'C', 'Organisasi Sosial', 130),
(290, 3303064, 'RS Umum Nirmala', 'RSU', 'C', 'Organisasi Sosial', 91),
(291, 3303016, 'RS Umum Daerah dr. R. Goeteng  Taroenadibrata', 'RSU', 'C', 'Pemkab', 266),
(292, 3302224, 'RS Umum Siaga Medika Banyumas', 'RSU', 'C', 'Organisasi Sosial', 223),
(293, 3302213, 'RS Umum Wiradadi Husada', 'RSU', 'C', 'Organisasi Sosial', 102),
(294, 3302191, 'RS Umum Daerah Ajibarang', 'RSU', 'C', 'Pemkab', 165),
(295, 3302180, 'RS Umum Sinar Kasih', 'RSU', 'D', 'Organisasi Sosial', 49),
(296, 3302165, 'RS Umum Ananda Purwokerto', 'RSU', 'C', 'Organisasi Sosial', 91),
(297, 3302154, 'RS Umum Bunda', 'RSU', 'D', 'Organisasi Sosial', 56),
(298, 3302143, 'RS Umum Hidayah Purwokerto', 'RSU', 'D', 'Swasta', 53),
(299, 3302132, 'RS Umum Islam Purwokerto', 'RSU', 'D', 'Organisasi Islam', 82),
(300, 3302041, 'RS Umum Santa Elisabeth Purwokerto', 'RSU', 'C', 'Organisasi Katholik', 90),
(301, 3302030, 'RS Umum Tk III Wijayakusuma', 'RSU', 'C', 'TNI AD', 203),
(302, 3302026, 'RS Umum Daerah Prof Dr. Margono  Soekarjo Purwoker', 'RSU', 'B', 'Pemprop', 666),
(303, 3302015, 'RSUD BANYUMAS', 'RSU', 'B', 'Pemkab', 440),
(304, 3301105, 'RS Umum Aprilia', 'RSU', 'C', 'Organisasi Sosial', 46),
(305, 3301095, 'RS Bersalin Annisa', 'RSIA', 'C', 'Organisasi Islam', 25),
(306, 3301084, 'RS Umum Daerah Majenang', 'RSU', 'C', 'Pemkab', 135),
(307, 3301073, 'RS Umum Islam Fatimah', 'RSU', 'C', 'Organisasi Islam', 185),
(308, 3301036, 'RS Umum Pertamina Cilacap', 'RSU', 'D', 'BUMN', 51),
(309, 3301014, 'RS Umum Daerah Cilacap', 'RSU', 'B', 'Pemkab', 288),
(310, 0, 'tablescraper-selected-row 3', 'tablescraper-selected-row 4', 'tablescrap', 'tablescraper-selected-row 6', 0),
(311, 3212031, 'RS Umum Daerah M.A. Sentot Patrol', 'RSU', 'C', 'Pemkab', 132),
(312, 3212016, 'RS Umum Daerah Kab. Indramayu', 'RSU', 'B', 'Pemkab', 12),
(313, 3211026, 'RS Umum Pakuwon', 'RSU', 'C', 'Swasta', 109),
(314, 3211015, 'RS Umum Daerah Sumedang', 'RSU', 'B', 'Pemkab', 327),
(315, 3210036, 'RS Bedah Budi Kasih', 'RSK BEDAH', 'C', 'Organisasi Sosial', 16),
(316, 3210025, 'RS Umum Daerah Cideres', 'RSU', 'C', 'Pemkab', 240),
(317, 3210014, 'RS Umum Daerah Majalengka', 'RSU', 'C', 'Pemkab', 209),
(318, 3209051, 'RS Umum Mitra Plumbon', 'RSU', 'B', 'Swasta', 290),
(319, 3209040, 'RS Umum Daerah Arjawinangun', 'RSU', 'B', 'Pemkab', 376),
(320, 3209036, 'RS Paru Provinsi Jawa Barat', 'RSK PARU', 'B', 'Pemprop', 108),
(321, 3209025, 'RS Pertamina Cirebon', 'RSU', 'C', 'Swasta', 90),
(322, 3209014, 'RS Umum Daerah Waled', 'RSU', 'B', 'Pemkab', 246),
(323, 3208035, 'RS Umum Sekar Kamulyan', 'RSU', 'C', 'Organisasi Sosial', 107),
(324, 3208024, 'RS Umum Wijaya Kusumah', 'RSU', 'C', 'Organisasi Sosial', 121),
(325, 3208013, 'RS Umum Daerah 45 Kuningan', 'RSU', 'B', 'Pemkab', 169),
(326, 3207045, 'RS Umum Permata Bunda', 'RSU', 'D', 'Organisasi Sosial', 75),
(327, 3207023, 'RS Umum Daerah Banjar', 'RSU', 'B', 'Pemkot', 311),
(328, 3207012, 'RS Umum Daerah Kab. Ciamis', 'RSU', 'C', 'Pemkab', 312),
(329, 3278081, 'RS Umum Prasetya Bunda', 'RSU', 'D', 'Swasta', 43),
(330, 3206070, 'RS Umum Jasa Kartini', 'RSU', 'C', 'Perusahaan', 188),
(331, 3206055, 'RS Umum Islam Hj. Siti Muniroh', 'RSU', 'D', 'Organisasi Islam', 29),
(332, 3206011, 'RS Umum Daerah dr. Soekardjo', 'RSU', 'B', 'Pemkot', 423),
(333, 3205021, 'RS Umum Tk IV Guntur', 'RSU', 'C', 'TNI AD', 127),
(334, 3205010, 'RS Umum Daerah dr. Slamet Garut', 'RSU', 'B', 'Pemkab', 449),
(335, 3204101, 'RS Umum Daerah Cicalengka', 'RSU', 'C', 'Pemkab', 71),
(336, 3204090, 'RS Umum Daerah Soreang', 'RSU', 'C', 'Pemkab', 201),
(337, 3204086, 'RS Umum Daerah Al Ihsan Provinsi Jawa Barat', 'RSU', 'B', 'Pemprop', 331),
(338, 3204075, 'RS Umum Mitra Kasih', 'RSU', 'C', 'Organisasi Sosial', 148),
(339, 3217042, 'RS Jiwa Provinsi Jawa Barat', 'RSK Jiwa', 'A', 'Pemprop', 209),
(340, 3277031, 'RS Umum Tk II Dustira', 'RSU', 'B', 'TNI AD', 447),
(341, 3277020, 'RS Umum Daerah Cibabat', 'RSU', 'B', 'Pemkot', 269),
(342, 3204016, 'RS Umum Daerah Majalaya', 'RSU', 'B', 'Pemkab', 191),
(343, 3203037, 'RS Umum Daerah Cimacan', 'RSU', 'C', 'Pemkab', 137),
(344, 3203015, 'RS Umum Daerah Sayang', 'RSU', 'B', 'Pemkab', 516),
(345, 3202062, 'RS Umum Hermina', 'RSU', 'C', 'Swasta', 110),
(346, 3202051, 'RS Umum Daerah Jampang Kulon', 'RSU', 'C', 'Pemprop', 146),
(347, 3202040, 'RS Umum Daerah Palabuhanratu', 'RSU', 'C', 'Pemkab', 166),
(348, 3202014, 'RS Umum Daerah Sekarwangi', 'RSU', 'B', 'Pemkab', 199),
(349, 3201218, 'RS Umum Islam Bogor', 'RSU', 'C', 'Organisasi Sosial', 114),
(350, 3201207, 'RS Umum MH. Thamrin', 'RSU', 'C', 'Swasta', 121),
(351, 3201196, 'RS Umum Bunda Margonda', 'RSU', 'C', 'Swasta', 64),
(352, 3201185, 'RS Umum Meilia', 'RSU', 'B', 'Swasta', 166),
(353, 3201152, 'RS Umum Mary Cileungsi Hijau', 'RSU', 'C', 'Swasta', 129),
(354, 3201141, 'RS Ibu dan Anak Tumbuh Kembang', 'RSIA', 'C', 'Organisasi Sosial', 66),
(355, 3201130, 'RS Ibu dan Anak Citra Insani', 'RSIA', 'C', 'Swasta', 62),
(356, 3201126, 'RS Umum Hermina Depok', 'RSU', 'B', 'Organisasi Sosial', 183),
(357, 3201115, 'RS Umum Bina Husada', 'RSU', 'C', 'Swasta', 112),
(358, 3201072, 'RS Umum Puri Cinere', 'RSU', 'B', 'Swasta', 120),
(359, 3201061, 'RS Umum Tugu Ibu', 'RSU', 'C', 'Organisasi Sosial', 114),
(360, 3201050, 'RS Umum Daerah Ciawi', 'RSU', 'B', 'Pemkab', 290),
(361, 3201046, 'RS Umum Daerah Cibinong', 'RSU', 'B', 'Pemkab', 349),
(362, 3201035, 'RS Umum Bhakti Yudha', 'RSU', 'C', 'Organisasi Sosial', 104),
(363, 3201024, 'RS Paru Dr. M. Goenawan Partowidigdo', 'RSK PARU', 'B', 'Kemkes', 177),
(364, 3201013, 'RS Umum Harapan Depok', 'RSU', 'D', 'Organisasi Sosial', 45),
(365, 3210038, '', 'RSIA', 'C', 'Swasta', 119),
(366, 0, 'nama_rumah_sakit', 'jenis_rs', 'kelas_rs', 'pemilik', 0);

-- --------------------------------------------------------

--
-- Struktur dari tabel `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `address` text DEFAULT NULL,
  `age` int(11) DEFAULT NULL,
  `gender` enum('male','female') NOT NULL,
  `category_diabetes` enum('non-diabetes','diabetes 1','diabetes 2') NOT NULL,
  `role` enum('User','admin') DEFAULT 'User',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data untuk tabel `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `password`, `address`, `age`, `gender`, `category_diabetes`, `role`, `created_at`, `updated_at`) VALUES
(1, 'John Doe', 'john@example.com', 'scrypt:32768:8:1$RI1nUzuq1a9HVDqy$16b5f2e40ae8059161d5f81cea4defe81897f7e4180a2aaeca63d3b5fb0815a1b56e9a4ee1434562676bc435a6df0685bcd124cccfa217f2050b70bc5f032edf', '123 Main St', 30, 'male', 'non-diabetes', 'User', '2024-10-20 05:39:22', '2024-10-20 05:39:22'),
(2, 'Jane Smith', 'jane@example.com', 'scrypt:32768:8:1$6K7ZZFY8shlpM2hJ$95473f3883a977a9c04912aa69e8dec9812658f7e681944db24c6e602ab74dda9de98a422acf747dc5b6591e36daa7ddebc6db27d94cd07830544db78b141768', '456 Elm St', 25, 'female', 'diabetes 1', 'User', '2024-10-20 05:39:22', '2024-10-20 05:39:22'),
(3, 'Admin User', 'admin@example.com', 'scrypt:32768:8:1$4vYUO7o8wkOuoHmT$560430544e21dd7da32301eec115f06ba7fb70b9c7b33a14a796b0f10eaf559368540fa6382f9dfd8a713f98c01fc1fe37b4cd67977c441ed32685c47d8f7bd3', '789 Oak St', 35, 'male', 'non-diabetes', 'admin', '2024-10-20 05:39:22', '2024-10-20 05:39:22');

--
-- Indexes for dumped tables
--

--
-- Indeks untuk tabel `articles`
--
ALTER TABLE `articles`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indeks untuk tabel `rumah_sakit`
--
ALTER TABLE `rumah_sakit`
  ADD PRIMARY KEY (`id`);

--
-- Indeks untuk tabel `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT untuk tabel yang dibuang
--

--
-- AUTO_INCREMENT untuk tabel `articles`
--
ALTER TABLE `articles`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT untuk tabel `rumah_sakit`
--
ALTER TABLE `rumah_sakit`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=367;

--
-- AUTO_INCREMENT untuk tabel `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- Ketidakleluasaan untuk tabel pelimpahan (Dumped Tables)
--

--
-- Ketidakleluasaan untuk tabel `articles`
--
ALTER TABLE `articles`
  ADD CONSTRAINT `articles_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
