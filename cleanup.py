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
JUNK = 'Junk'
SIMILARITY_THRESH = 8
SUPPORTED_FILE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif']


def get_args():
    parser = argparse.ArgumentParser(description='Clean up image files', add_help=False, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--help', action="help")
    #parser.add_argument('-r', '--rename-similar', action='store_true', help="Group together similar-looking images for easy removal")
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
    print filename, w, h
    if w < MIN_W or h < MIN_H:
        return True


def load_image(filename):
    """Load an image and resize it with OpenCV"""
    img = cv2.imread(filename, 0) # 0 = greyscale
    if img is None:
        return None

    try:
        img = cv2.resize(img, SIZE)
    except cv2.error, e:
        print 'Error loading', filename
        raise e
    return img


def compute_dct(img):
    """Get the discrete cosine transform of an image"""
    return np.uint8(cv2.dct(np.float32(img)/255.0)*255)


def compute_phash(filename):
    """Compute a perceptual hash of an image"""
    img = load_image(filename)
    if img is None:
        return None
    dct = compute_dct(img)
    dct = dct[:HASH_DIM[0], :HASH_DIM[1]]
    avg = np.average(dct)
    bits = [(x > avg) for x in dct.flatten()]
    return sum([2**i * int(bits[i]) for i in range(len(bits))])


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
                if c not in visited:
                    visited.add(c)
                    component.append(c)
                    dfs(visited, component, c)
        except KeyError:
            pass

        return component

    visited = set()
    components = {}
    for i in amalgams:
        if i not in visited:
            visited.add(i)
            components[i] = dfs(visited, [i], i)

    return components


def read_cache():
    try:
        fd = open(CACHE_FILE, 'r')
    except:
        raise ValueError('Could not open cache file')

    cache = {}
    for line in fd.readlines():
        line = line.split()
        try:
            cache[line[0]] = {'mtime': int(line[1]), 'phash': int(line[2])}
        except:
            pass

    fd.close()

    return cache


def write_cache(files, hashes):
    try:
        fd = open(CACHE_FILE, 'w')
    except:
        raise ValueError('Could not open cache file for writing')

    for file, hash in zip(files, hashes):
        mtime = int(os.path.getmtime(file))
        fd.write('%s %s %s\n' % (file, mtime, hash))

    fd.close()


def sort_files(cache):
    # Prepends 0 to the filename if we've seen the file before  this
    # ensures we never touch files that have already dealt with
    def _sort_files(name):
        return str(int(name not in cache)) + name

    return _sort_files


def create_folder(name):
    if not os.path.exists(name):
        try:
            os.mkdir(name)
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

    if remove_small:
        create_folder(JUNK)

    duplicate_folder_relative_path = ''
    if move_suspected_duplicates:
        directory_name = os.path.basename(folder)
        duplicate_folder_relative_path = os.path.join('../', '[Dupes] ' + directory_name)
        create_folder(duplicate_folder_relative_path)
        
    try:
        cache = read_cache()
    except ValueError:
        print 'Error reading cache file; ignoring'
        cache = {}

    # Recursively compute phash for all supported images, or extract the cached one.
    hashes = []
    files = []

    for root, dir_list, file_list in os.walk('.'):
        for file in [f for f in file_list if os.path.splitext(f)[1].lower() in SUPPORTED_FILE_EXTENSIONS]:
            file = os.path.join(root, file)

            # Move the file away if it's too small
            if remove_small and too_small(file):
                try:
                    os.rename(file, os.path.join(JUNK, file))
                    print 'Moving %s to junk as it is too small.' % (file)
                except OSError, e:
                    print 'Failed to move %s: %s' % (file, e)
                continue

            try:
                # Get cached info
                if cache[file]['mtime'] == int(os.path.getmtime(file)):
                    phash = cache[file]['phash']
                else:
                    # update hash if file has been modified since cached result
                    phash = compute_phash(file)
                    if phash:
                        print '%s %x' % (file, phash)
            except KeyError:
                # Compute hashes of uncached files and print to show we're doing stuff
                phash = compute_phash(file)
                if phash:
                    print '%s %x' % (file, phash)

            files.append(file)
            hashes.append(phash)

    print 'Finished gathering hashes for %s files in %s' % (len(files), folder)

    # Find pairs of images whose phash is similar
    amalgams = defaultdict(list)
    for i, file_a in enumerate(files):
        if hashes[i] is None:
            continue
        for j, file_b in enumerate(files[i+1:]):
            j += i+1
            if hashes[j] is None:
                continue
            if hamming(hashes[i], hashes[j]) < SIMILARITY_THRESH:
                amalgams[file_a].append(file_b)
                amalgams[file_b].append(file_a)

    # Group together all images which are similar
    amalgams = dict(amalgams)
    amalgams = amalgamate(amalgams)

    # Rename similar files to to be <name>.jpg, <name>_v1.jpg, <name>_v2.jpg etc
    for similar in amalgams.values():
        similar.sort(key=sort_files(cache))

        # Alphabetically first file retains its filename
        original_filename_without_extension = os.path.splitext(similar[0])[0]

        if move_suspected_duplicates:
            print 'Moving original file %s to duplicates directory' % similar[0]
            duplicate_file_path = os.path.join(duplicate_folder_relative_path, similar[0])
            duplicate_file_directory = os.path.dirname(duplicate_file_path)
            create_folder(duplicate_file_directory)
            os.rename(similar[0], duplicate_file_path)
            index_to_remove = files.index(similar[0])
            del files[index_to_remove]
            del hashes[index_to_remove]

        for i, oldname in enumerate(similar[1:], 1):
            ext = os.path.splitext(oldname)[1]
            newname = '%s_v%d%s' % (original_filename_without_extension, i, ext)
            if move_suspected_duplicates:
                newname = os.path.join(duplicate_folder_relative_path, newname)

            # Don't try to rename things to themselves
            if oldname != newname:
                # Don't overwrite existing files
                if os.path.exists(newname):
                    print 'I want to rename %s to %s but the latter already exists.' % (oldname, newname)
                    continue
                try:
                    os.rename(oldname, newname)
                    if move_suspected_duplicates:
                        print 'Moving suspected duplicate %s to %s.' % (oldname, duplicate_folder_relative_path)
                        index_to_remove = files.index(oldname)
                        del files[index_to_remove]
                        del hashes[index_to_remove]
                    else:
                        print 'Renaming %s to %s due to similarities.' % (oldname, newname)
                        files[files.index(oldname)] = newname
                except OSError, e:
                    print 'Failed to rename %s: %s' % (oldname, e)
                    continue

    write_cache(files, hashes)

    print 'Done.'

