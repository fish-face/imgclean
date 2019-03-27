#!/usr/bin/env python

import cv2
from PIL import Image
import numpy as np
import sys
import os
from glob import glob
from collections import defaultdict
import argparse

MIN_W, MIN_H = 1200, 1200*9.0/16
SIZE = (64, 36)  # 16:9
HASH_DIM = (8, 8)
HASH_SIZE = HASH_DIM[0] * HASH_DIM[1]
CACHE_FILE = 'fingerprint.db'
JUNK_FOLDER_PREFIX = '[Junk]'
DUPE_FOLDER_PREFIX = '[Dupes]'
SIMILARITY_THRESH = 8
SUPPORTED_FILE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif']


class FileInfo:
    def __init__(self, filepath):
        self.filepath = filepath
        self.phash = None
        self.width = None
        self.height = None


def get_args():
    parser = argparse.ArgumentParser(description='Clean up image files', add_help=False, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--help', action="help")
    #parser.add_argument('-r', '--rename-similar', action='store_true', help="Group together similar-looking images for easy removal")
    parser.add_argument('-r', '--recursive', action='store_true', help="Recurse into subfolders of the target folder")
    parser.add_argument('-s', '--remove-small', action='store_true', help="Move images smaller than a certain threshold to a separate directory")
    parser.add_argument('-d', '--move-suspected-duplicates', action='store_true', help="Move all suspected duplicates (including original) into a separate directory")
    parser.add_argument('-w', '--min-width', default=MIN_W, help="Minimum width")
    parser.add_argument('-h', '--min-height', default=MIN_H, help="Minimum height")
    parser.add_argument('-t', '--threshold', default=SIMILARITY_THRESH, help="Threshold below which images are too similar")
    parser.add_argument('folder', nargs='?', default='.', help="Folder to scan")

    return parser.parse_args()

def too_small(filename):
    """Test if an image file is too small"""
    try:
        img = Image.open(filename)
    except IOError:
        # Probably not an image
        return False
    w, h = img.size
    if w < MIN_W or h < MIN_H:
        return True


def load_image(fileinfo):
    """Load an image and resize it with OpenCV"""
    cv2_load_method = 0
    if hasattr(cv2, 'CV_LOAD_IMAGE_GRAYSCALE'):
        cv2_load_method = cv2.CV_LOAD_IMAGE_GRAYSCALE
    elif hasattr(cv2, 'IMREAD_GRAYSCALE'):
        cv2_load_method = cv2.IMREAD_GRAYSCALE
    else:
        print 'Aborting. Your CV2 version does not appear to support loading images as greyscale.'
        exit()

    img = cv2.imread(fileinfo.filepath, cv2_load_method)
    if img is None:
        return None

    # store original height & width; to be used later to determine "best" copy of image
    fileinfo.height, fileinfo.width = img.shape

    try:
        img = cv2.resize(img, SIZE)
    except cv2.error, e:
        print 'Error loading', fileinfo.filepath
        raise e
    return img


def compute_dct(img):
    """Get the discrete cosine transform of an image"""
    return np.uint8(cv2.dct(np.float32(img)/255.0)*255)


def compute_phash(fileinfo):
    """Compute a perceptual hash of an image"""
    img = load_image(fileinfo)
    if img is None:
        return None
    dct = compute_dct(img)
    dct = dct[:HASH_DIM[0], :HASH_DIM[1]]
    avg = np.average(dct)
    bits = [(x > avg) for x in dct.flatten()]
    fileinfo.phash = sum([2**i * int(bits[i]) for i in range(len(bits))])


def hamming(h1, h2):
    """Compute the hamming distance (as binary strings) between two integers"""
    h, d = 0, h1 ^ h2
    while d:
        h += 1
        d &= d - 1
    return h


def amalgamate(amalgams):
    """Collapse a graph described by a dict into connected components"""
    def dfs(visited, component, current):
        try:
            for c in amalgams[current]:
                if c.filepath not in visited:
                    visited.add(c.filepath)
                    component.append(c)
                    dfs(visited, component, c)
        except KeyError:
            pass

        return component

    visited = set()
    components = {}
    for i in amalgams:
        if i.filepath not in visited:
            visited.add(i.filepath)
            components[i] = dfs(visited, [i], i)

    return components


def read_cache():
    try:
        fd = open(CACHE_FILE, 'r')
    except:
        raise ValueError('Could not open cache file')

    cache = {}
    for line in fd.readlines():
        line = line.split('\t')
        try:
            cache[line[0]] = {'mtime': int(line[1]), 'phash': int(line[2]), 'width': int(line[3]), 'height': int(line[4])}
        except:
            pass

    fd.close()

    return cache


def write_cache(fileinfos):
    if len(fileinfos) == 0:
        return

    try:
        fd = open(CACHE_FILE, 'w')
    except:
        raise ValueError('Could not open cache file for writing')

    for fileinfo in fileinfos:
        mtime = int(os.path.getmtime(fileinfo.filepath))
        fd.write('%s\t%s\t%s\t%s\t%s\n' % (fileinfo.filepath, mtime, fileinfo.phash, fileinfo.width, fileinfo.height))

    fd.close()

def sort_by_pixel_area(fileinfo):
    return fileinfo.height * fileinfo.width


def create_folder(name):
    if not os.path.exists(name):
        try:
            os.makedirs(name)
            print "Creating '%s' folder" % name
        except OSError:
            print "Could not create '%s' folder" % name
            sys.exit(1)
    elif not os.path.isdir(name):
        print "A file named '%s' exists and it is not a directory." % name
        sys.exit(1)

if __name__ == '__main__':
    locals().update(vars(get_args()))

    try:
        os.chdir(folder)
    except OSError:
        print 'Invalid path: %s' % (folder)
        sys.exit(1)
    # File operations are now relative to source directory
    
    print "Begin processing root image directory '%s'" % folder

    directory_name = os.path.basename(os.path.normpath(folder))

    junk_folder_relative_path = ''
    if remove_small:
        junk_folder_relative_path = os.path.join('..', JUNK_FOLDER_PREFIX + directory_name)
        create_folder(junk_folder_relative_path)

    duplicate_folder_relative_path = ''
    if move_suspected_duplicates:
        duplicate_folder_relative_path = os.path.join('..', DUPE_FOLDER_PREFIX + directory_name)
        create_folder(duplicate_folder_relative_path)
        
    try:
        cache = read_cache()
    except ValueError:
        print 'Error reading cache file; ignoring'
        cache = {}

    _print_counter = 0
    def _print_progress(char):
        global _print_counter
        _print_counter += 1
        sys.stdout.write(char)
        if _print_counter > 80:
            sys.stdout.write("\n")
            _print_counter = 0

    # Recursively compute phash for all supported images, or extract the cached one.
    fileinfos = []
    for root, dir_list, file_list in os.walk('.'):
        print "\nBegin hashing directory '%s':" % root
        _print_counter = 0
        for file in [f for f in file_list if os.path.splitext(f)[1].lower() in SUPPORTED_FILE_EXTENSIONS]:
            file = os.path.join(root, file)
            fileinfo = FileInfo(file)

            # Move the file away if it's too small
            if remove_small and too_small(file):
                try:
                    junk_file_path = os.path.join(junk_folder_relative_path, file)
                    junk_file_directory = os.path.dirname(junk_file_path)
                    create_folder(junk_file_directory)
                    os.rename(file, junk_file_path)
                    print 'Moving %s to junk as it is too small.' % (file)
                except OSError, e:
                    print 'Failed to move %s: %s' % (file, e)
                continue

            try:
                # Get cached info
                if cache[file]['mtime'] == int(os.path.getmtime(file)):
                    for var in ('phash', 'width', 'height'):
                        setattr(fileinfo, var, cache[file][var])
                else:
                    # update hash if file has been modified since cached result
                    compute_phash(fileinfo)
                    if fileinfo.phash:
                        _print_progress('+') # + represents updating known hash
            except KeyError:
                # Compute hashes of uncached files
                compute_phash(fileinfo)
                if fileinfo.phash:
                    _print_progress('.') # . represents calculating new hash

            fileinfos.append(fileinfo)
        print "done"

        if not recursive:
            break

    print '\nFinished gathering hashes for %s files in %s\n' % (len(fileinfos), folder)

    # Find pairs of images whose phash is similar
    amalgams = defaultdict(list)
    for i, file_a in enumerate(fileinfos):
        if file_a.phash is None:
            continue
        for file_b in fileinfos[i+1:]:
            if file_b.phash is None:
                continue
            if hamming(file_a.phash, file_b.phash) < SIMILARITY_THRESH:
                amalgams[file_a].append(file_b)
                amalgams[file_b].append(file_a)

    # Group together all images which are similar
    amalgams = dict(amalgams)
    amalgams = amalgamate(amalgams)

    # Rename similar files to to be <name>.jpg, <name>_v1.jpg, <name>_v2.jpg etc
    for similar in amalgams.values():
        # sort to prefer the largest (pixel area) image first
        similar.sort(key = sort_by_pixel_area, reverse = True)
        master_filepath = similar[0].filepath
        master_filename_without_extension = os.path.splitext(master_filepath)[0]

        if move_suspected_duplicates:
            print 'Moving master file %s to duplicates directory' % master_filepath
            duplicate_file_path = os.path.join(duplicate_folder_relative_path, master_filepath)
            duplicate_file_directory = os.path.dirname(duplicate_file_path)
            create_folder(duplicate_file_directory)
            os.rename(master_filepath, duplicate_file_path)
            index_to_remove = [i for i, f in enumerate(fileinfos) if f.filepath == master_filepath][0]
            del fileinfos[index_to_remove]

        for i, duplicate_fileinfo in enumerate(similar[1:], 1):
            duplicate_filepath = duplicate_fileinfo.filepath
            ext = os.path.splitext(duplicate_filepath)[1]
            new_duplicate_filepath = '%s_v%d%s' % (master_filename_without_extension, i, ext)
            if move_suspected_duplicates:
                new_duplicate_filepath = os.path.join(duplicate_folder_relative_path, new_duplicate_filepath)

            # Don't try to rename things to themselves
            if duplicate_filepath != new_duplicate_filepath:
                # Don't overwrite existing files
                if os.path.exists(new_duplicate_filepath):
                    print 'I want to rename %s to %s but the latter already exists.' % (duplicate_filepath, new_duplicate_filepath)
                    continue
                try:
                    os.rename(duplicate_filepath, new_duplicate_filepath)
                    fileinfo_index_to_update = [i for i, f in enumerate(fileinfos) if f.filepath == duplicate_filepath][0]
                    if move_suspected_duplicates:
                        print 'Moving suspected duplicate %s to duplicates directory.' % (duplicate_filepath)
                        del fileinfos[fileinfo_index_to_update]
                    else:
                        print 'Renaming %s to %s due to similarities.' % (duplicate_filepath, new_duplicate_filepath)
                        fileinfos[fileinfo_index_to_update].filepath = new_duplicate_filepath
                except OSError, e:
                    print 'Failed to rename %s: %s' % (duplicate_filepath, e)
                    continue

    write_cache(fileinfos)

    print '\nCleanup complete.'

