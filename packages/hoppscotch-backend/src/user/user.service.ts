import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as O from 'fp-ts/Option';
import * as E from 'fp-ts/Either';
import * as TO from 'fp-ts/TaskOption';
import * as TE from 'fp-ts/TaskEither';
import * as T from 'fp-ts/Task';
import * as A from 'fp-ts/Array';
import { pipe, constVoid } from 'fp-ts/function';
import { AuthUser } from 'src/types/AuthUser';
import {
  USERS_NOT_FOUND,
  USER_NOT_FOUND,
  USER_SHORT_DISPLAY_NAME,
} from 'src/errors';
import { SessionType, User } from './user.model';
import { USER_UPDATE_FAILED } from 'src/errors';
import { PubSubService } from 'src/pubsub/pubsub.service';
import { encrypt, stringToJson, taskEitherValidateArraySeq } from 'src/utils';
import { UserDataHandler } from './user.data.handler';
import { User as DbUser } from '@prisma/client';
import { OffsetPaginationArgs } from 'src/types/input-types.args';
import { GetUserWorkspacesResponse } from 'src/infra-token/request-response.dto';
import { TeamAccessRole } from 'src/team/team.model';

@Injectable()
export class UserService {
  constructor(
    private prisma: PrismaService,
    private readonly pubsub: PubSubService,
  ) {}

  private userDataHandlers: UserDataHandler[] = [];

  registerUserDataHandler(handler: UserDataHandler) {
    this.userDataHandlers.push(handler);
  }

  /**
   * Converts a prisma user object to a user object
   *
   * @param dbUser Prisma User object
   * @returns  User object
   */
  convertDbUserToUser(dbUser: DbUser): User {
    const dbCurrentRESTSession = dbUser.currentRESTSession;
    const dbCurrentGQLSession = dbUser.currentGQLSession;

    return {
      ...dbUser,
      currentRESTSession: dbCurrentRESTSession
        ? JSON.stringify(dbCurrentRESTSession)
        : null,
      currentGQLSession: dbCurrentGQLSession
        ? JSON.stringify(dbCurrentGQLSession)
        : null,
    };
  }

  /**
   * Find User with given email id
   *
   * @param email User's email
   * @returns Option of found User
   */
  async findUserByEmail(email: string): Promise<O.None | O.Some<AuthUser>> {
    const user = await this.prisma.user.findFirst({
      where: {
        email: {
          equals: email,
          mode: 'insensitive',
        },
      },
    });
    if (!user) return O.none;
    return O.some(user);
  }
  /**
   * Find User with given email id
   *
   * @param username User's name
   * @returns Option of found User
   */
  async findUserByUsername(
    username: string,
  ): Promise<O.None | O.Some<AuthUser>> {
    console.log('username', username)
    const user = await this.prisma.user.findFirst({
      where: {
        AND: {
          username: {
            equals: username,
            mode: "default"
          },
        }
      },
    });
    console.log(user);
    if (!user) return O.none;
    return O.some(user);
  }

  /**
   * Find User with given ID
   *
   * @param userUid User ID
   * @returns Option of found User
   */
  async findUserById(userUid: string): Promise<O.None | O.Some<AuthUser>> {
    try {
      const user = await this.prisma.user.findUniqueOrThrow({
        where: {
          uid: userUid,
        },
      });
      return O.some(user);
    } catch (error) {
      return O.none;
    }
  }

  /**
   * Find users with given IDs
   * @param userUIDs User IDs
   * @returns Array of found Users
   */
  async findUsersByIds(userUIDs: string[]): Promise<AuthUser[]> {
    const users = await this.prisma.user.findMany({
      where: {
        uid: { in: userUIDs },
      },
    });
    return users;
  }

  /**
   * Update User with new generated hashed refresh token
   *
   * @param refreshTokenHash Hash of newly generated refresh token
   * @param userUid User uid
   * @returns Either of User with updated refreshToken
   */
  async updateUserRefreshToken(refreshTokenHash: string, userUid: string) {
    try {
      const user = await this.prisma.user.update({
        where: {
          uid: userUid,
        },
        data: {
          refreshToken: refreshTokenHash,
        },
      });

      return E.right(user);
    } catch (error) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Create a new User when logged in via a Magic Link
   *
   * @param email User's Email
   * @returns Created User
   */
  async createUserViaMagicLink(email: string) {
    const createdUser = await this.prisma.user.create({
      data: {
        email: email,
        providerAccounts: {
          create: {
            provider: 'magic',
            providerAccountId: email,
          },
        },
      },
    });

    return createdUser;
  }
  /**
   * Create a new User when logged in via a Magic Link
   *
   * @param email User's Email
   * @returns Created User
   */
  async createUserByUserAndPass(user: string, pass: string) {
    const createdUser = await this.prisma.user.create({
      data: {
        username: user,
        password: pass,
      },
    });

    return createdUser;
  }
  /**
   * Create a new User when logged in via a SSO provider
   *
   * @param accessTokenSSO  User's access token generated by providers
   * @param refreshTokenSSO User's refresh token generated by providers
   * @param profile Data received from SSO provider on the users account
   * @returns Created User
   */
  async createUserSSO(
    accessTokenSSO: string,
    refreshTokenSSO: string,
    profile,
  ) {
    const userDisplayName = !profile.displayName ? null : profile.displayName;
    const userPhotoURL = !profile.photos ? null : profile.photos[0].value;

    const createdUser = await this.prisma.user.create({
      data: {
        displayName: userDisplayName,
        email: profile.emails[0].value,
        photoURL: userPhotoURL,
        lastLoggedOn: new Date(),
        providerAccounts: {
          create: {
            provider: profile.provider,
            providerAccountId: profile.id,
            providerRefreshToken: refreshTokenSSO,
            providerAccessToken: accessTokenSSO,
          },
        },
      },
    });

    return createdUser;
  }

  /**
   * Create a new  Account for a given User
   *
   * @param user User object
   * @param accessToken User's access token generated by providers
   * @param refreshToken User's refresh token generated by providers
   * @param profile Data received from SSO provider on the users account
   * @returns Created Account
   */
  async createProviderAccount(
    user: AuthUser,
    accessToken: string,
    refreshToken: string,
    profile,
  ) {
    const createdProvider = await this.prisma.account.create({
      data: {
        provider: profile.provider,
        providerAccountId: profile.id,
        providerRefreshToken: refreshToken ? encrypt(refreshToken) : null,
        providerAccessToken: accessToken ? encrypt(accessToken) : null,
        user: {
          connect: {
            uid: user.uid,
          },
        },
      },
    });

    return createdProvider;
  }

  /**
   * Update User displayName and photoURL when logged in via a SSO provider
   *
   * @param user User object
   * @param profile Data received from SSO provider on the users account
   * @returns Updated user object
   */
  async updateUserDetails(user: AuthUser, profile) {
    try {
      const updatedUser = await this.prisma.user.update({
        where: {
          uid: user.uid,
        },
        data: {
          displayName: !profile.displayName ? null : profile.displayName,
          photoURL: !profile.photos ? null : profile.photos[0].value,
          lastLoggedOn: new Date(),
        },
      });
      return E.right(updatedUser);
    } catch (error) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Update a user's sessions
   * @param user User object
   * @param currentRESTSession user's current REST session
   * @param currentGQLSession user's current GQL session
   * @returns a Either of User or error
   */
  async updateUserSessions(
    user: AuthUser,
    currentSession: string,
    sessionType: string,
  ): Promise<E.Right<User> | E.Left<string>> {
    const validatedSession = await this.validateSession(currentSession);
    if (E.isLeft(validatedSession)) return E.left(validatedSession.left);

    try {
      const sessionObj = {};
      switch (sessionType) {
        case SessionType.GQL:
          sessionObj['currentGQLSession'] = validatedSession.right;
          break;
        case SessionType.REST:
          sessionObj['currentRESTSession'] = validatedSession.right;
          break;
        default:
          return E.left(USER_UPDATE_FAILED);
      }

      const dbUpdatedUser = await this.prisma.user.update({
        where: { uid: user.uid },
        data: sessionObj,
      });

      const updatedUser = this.convertDbUserToUser(dbUpdatedUser);

      // Publish subscription for user updates
      await this.pubsub.publish(`user/${updatedUser.uid}/updated`, updatedUser);

      return E.right(updatedUser);
    } catch (e) {
      return E.left(USER_UPDATE_FAILED);
    }
  }

  /**
   * Update a user's displayName
   * @param userUID User UID
   * @param displayName User's displayName
   * @returns a Either of User or error
   */
  async updateUserDisplayName(userUID: string, displayName: string) {
    if (!displayName || displayName.length === 0) {
      return E.left(USER_SHORT_DISPLAY_NAME);
    }

    try {
      const dbUpdatedUser = await this.prisma.user.update({
        where: { uid: userUID },
        data: { displayName },
      });

      const updatedUser = this.convertDbUserToUser(dbUpdatedUser);

      // Publish subscription for user updates
      await this.pubsub.publish(`user/${updatedUser.uid}/updated`, updatedUser);

      return E.right(updatedUser);
    } catch (error) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Update user's lastLoggedOn timestamp
   * @param userUID User UID
   */
  async updateUserLastLoggedOn(userUid: string) {
    try {
      await this.prisma.user.update({
        where: { uid: userUid },
        data: { lastLoggedOn: new Date() },
      });
      return E.right(true);
    } catch (e) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Update user's lastActiveOn timestamp
   * @param userUID User UID
   */
  async updateUserLastActiveOn(userUid: string) {
    try {
      await this.prisma.user.update({
        where: { uid: userUid },
        data: { lastActiveOn: new Date() },
      });
      return E.right(true);
    } catch (e) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Validate and parse currentRESTSession and currentGQLSession
   * @param sessionData string of the session
   * @returns a Either of JSON object or error
   */
  async validateSession(sessionData: string) {
    const jsonSession = stringToJson(sessionData);
    if (E.isLeft(jsonSession)) return E.left(jsonSession.left);

    return E.right(jsonSession.right);
  }

  /**
   * Fetch all the users in the `User` table based on cursor
   * @param cursorID string of userUID or null
   * @param take number of users to query
   * @returns an array of `User` object
   * @deprecated use fetchAllUsersV2 instead
   */
  async fetchAllUsers(cursorID: string, take: number) {
    const fetchedUsers = await this.prisma.user.findMany({
      skip: cursorID ? 1 : 0,
      take: take,
      cursor: cursorID ? { uid: cursorID } : undefined,
    });
    return fetchedUsers;
  }

  /**
   * Fetch all the users in the `User` table based on cursor
   * @param searchString search on user's displayName or email
   * @param paginationOption pagination options
   * @returns an array of `User` object
   */
  async fetchAllUsersV2(
    searchString: string,
    paginationOption: OffsetPaginationArgs,
  ) {
    const fetchedUsers = await this.prisma.user.findMany({
      skip: paginationOption.skip,
      take: paginationOption.take,
      where: searchString
        ? {
            OR: [
              {
                displayName: {
                  contains: searchString,
                  mode: 'insensitive',
                },
              },
              {
                email: {
                  contains: searchString,
                  mode: 'insensitive',
                },
              },
            ],
          }
        : undefined,
      orderBy: [{ isAdmin: 'desc' }, { displayName: 'asc' }],
    });

    return fetchedUsers;
  }

  /**
   * Fetch the number of users in db
   * @returns a count (Int) of user records in DB
   */
  async getUsersCount() {
    const usersCount = await this.prisma.user.count();
    return usersCount;
  }

  /**
   * Change a user to an admin by toggling isAdmin param to true
   * @param userUID user UID
   * @returns a Either of `User` object or error
   */
  async makeAdmin(userUID: string) {
    try {
      const elevatedUser = await this.prisma.user.update({
        where: {
          uid: userUID,
        },
        data: {
          isAdmin: true,
        },
      });
      return E.right(elevatedUser);
    } catch (error) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Change users to admins by toggling isAdmin param to true
   * @param userUID user UIDs
   * @returns a Either of true or error
   */
  async makeAdmins(userUIDs: string[]) {
    try {
      await this.prisma.user.updateMany({
        where: { uid: { in: userUIDs } },
        data: { isAdmin: true },
      });
      return E.right(true);
    } catch (error) {
      return E.left(USER_UPDATE_FAILED);
    }
  }

  /**
   * Fetch all the admin users
   * @returns an array of admin users
   */
  async fetchAdminUsers() {
    const admins = this.prisma.user.findMany({
      where: {
        isAdmin: true,
      },
    });

    return admins;
  }

  /**
   * Deletes a user account by UID
   * @param uid User UID
   * @returns an Either of string  or boolean
   */
  async deleteUserAccount(uid: string) {
    try {
      await this.prisma.user.delete({
        where: {
          uid: uid,
        },
      });
      return E.right(true);
    } catch (e) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Get user deletion error messages when the data handlers are initialised in respective modules
   * @param user User Object
   * @returns an TaskOption of string array
   */
  getUserDeletionErrors(user: AuthUser): TO.TaskOption<string[]> {
    return pipe(
      this.userDataHandlers,
      A.map((handler) =>
        pipe(
          handler.canAllowUserDeletion(user),
          TO.matchE(
            () => TE.right(undefined),
            (error) => TE.left(error),
          ),
        ),
      ),
      taskEitherValidateArraySeq,
      TE.matchE(
        (e) => TO.some(e),
        () => TO.none,
      ),
    );
  }

  /**
   * Deletes a user by UID
   * @param user User Object
   * @returns an TaskEither of string  or boolean
   */
  deleteUserByUID(user: AuthUser) {
    return pipe(
      this.getUserDeletionErrors(user),
      TO.matchEW(
        () =>
          pipe(
            this.userDataHandlers,
            A.map((handler) => handler.onUserDelete(user)),
            T.sequenceArray,
            T.map(constVoid),
            TE.fromTask,
          ) as TE.TaskEither<never, void>,
        (errors): TE.TaskEither<string[], void> => TE.left(errors),
      ),

      TE.chainW(() => () => this.deleteUserAccount(user.uid)),

      TE.chainFirst(() =>
        TE.fromTask(() =>
          this.pubsub.publish(`user/${user.uid}/deleted`, <User>{
            uid: user.uid,
            displayName: user.displayName,
            email: user.email,
            photoURL: user.photoURL,
            isAdmin: user.isAdmin,
            createdOn: user.createdOn,
            currentGQLSession: user.currentGQLSession,
            currentRESTSession: user.currentRESTSession,
          }),
        ),
      ),

      TE.mapLeft((errors) => errors.toString()),
    );
  }

  /**
   * Change the user from an admin by toggling isAdmin param to false
   * @param userUID user UID
   * @returns a Either of `User` object or error
   */
  async removeUserAsAdmin(userUID: string) {
    try {
      const user = await this.prisma.user.update({
        where: {
          uid: userUID,
        },
        data: {
          isAdmin: false,
        },
      });
      return E.right(user);
    } catch (error) {
      return E.left(USER_NOT_FOUND);
    }
  }

  /**
   * Change users from an admin by toggling isAdmin param to false
   * @param userUIDs user UIDs
   * @returns a Either of true or error
   */
  async removeUsersAsAdmin(userUIDs: string[]) {
    const data = await this.prisma.user.updateMany({
      where: { uid: { in: userUIDs } },
      data: { isAdmin: false },
    });

    if (data.count === 0) {
      return E.left(USERS_NOT_FOUND);
    }

    return E.right(true);
  }

  async fetchUserWorkspaces(userUid: string) {
    const user = await this.prisma.user.findUnique({ where: { uid: userUid } });
    if (!user) return E.left(USER_NOT_FOUND);

    const team = await this.prisma.team.findMany({
      where: {
        members: {
          some: {
            userUid,
          },
        },
      },
      include: {
        members: {
          select: {
            userUid: true,
            role: true,
          },
        },
      },
    });

    const workspaces: GetUserWorkspacesResponse[] = [];
    team.forEach((t) => {
      const ownerCount = t.members.filter(
        (m) => m.role === TeamAccessRole.OWNER,
      ).length;
      const editorCount = t.members.filter(
        (m) => m.role === TeamAccessRole.EDITOR,
      ).length;
      const viewerCount = t.members.filter(
        (m) => m.role === TeamAccessRole.VIEWER,
      ).length;
      const memberCount = t.members.length;

      workspaces.push({
        id: t.id,
        name: t.name,
        role: t.members.find((m) => m.userUid === userUid)?.role,
        owner_count: ownerCount,
        editor_count: editorCount,
        viewer_count: viewerCount,
        member_count: memberCount,
      });
    });
    return E.right(workspaces);
  }
}
